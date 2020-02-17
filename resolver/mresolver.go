package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

type MResolver struct {
	lk      sync.Mutex
	conn    dnsconn.Conn
	queries map[uint16]*mquery
	owners  map[uint16]chan error
	qid     uint32
}

type mquery struct {
	wait   sync.WaitGroup
	result func(string, []*dns.Record) error
	err    chan error
}

// NewMResolver creates a new client side IPC endpoint to talk to ns.MResolver
// conn must be stream oriented and connected to the server side of an ns.MResolver
func NewMResolver(conn dnsconn.Conn) *MResolver {
	r := &MResolver{
		conn:    conn,
		queries: make(map[uint16]*mquery),
		owners:  make(map[uint16]chan error),
	}

	go func() {
		var err error
		for {
			var msg *dns.Message

			msg, _, err = conn.ReadFromIf(context.Background(), nil)
			if err != nil {
				break
			}

			r.lk.Lock()
			qr, _ := r.queries[msg.ID]
			if qr != nil {
				qr.wait.Add(1)
			}
			o, ok := r.owners[msg.ID]
			if ok {
				if msg.RCode != dns.NoError {
					delete(r.owners, msg.ID)
				} else {
					o = nil
				}
			}
			if o != nil {
				o <- msg.RCode
			}
			r.lk.Unlock()

			if qr != nil {
				var iface string
				answers := msg.Answers

				if len(msg.Authority) > 0 {
					// first record denotes interface
					txt, _ := msg.Authority[0].D.(*dns.TXTRecord)
					if txt != nil {
						iface = txt.Text[0]
					}
				}
				if len(msg.Additional) > 0 && len(msg.Questions) > 0 {
					// first additional is NSEC negative cache, if present
					q := msg.Questions[0]
					rh := msg.Additional[0].H
					nsec, _ := msg.Additional[0].D.(*dns.NSECRecord)
					if nsec != nil && nsec.Next.Equal(rh.Name()) {
						if q.Type() != dns.AnyType && !nsec.Types.Is(q.Type()) {
							answers = append(answers, &dns.Record{
								H: dns.NewMDNSHeader(
									rh.Name(),
									q.Type(),
									rh.Class(),
									rh.TTL(),
									true,
								),
								D: nil,
							})
						}
					}
				}

				if err := qr.result(iface, answers); err != nil {
					qr.err <- err
					r.lk.Lock()
					delete(r.queries, msg.ID)
					r.lk.Unlock()
				}
				qr.wait.Done()
			}

		}

		r.lk.Lock()
		for _, mq := range r.queries {
			mq.err <- err
		}
		for _, o := range r.owners {
			o <- err
		}
		r.lk.Unlock()
	}()

	return r
}

// Close closes the underlying connection
func (r *MResolver) Close() error {
	return r.conn.Close()
}

// Query runs a persistent query asking q until ctx is done.
// Query is guaranteed to not return before result does, if it is called.
func (r *MResolver) Query(ctx context.Context, q []dns.Question, result func(string, []*dns.Record) error) error {
	var err error

	msg := &dns.Message{Opcode: dns.StandardQuery, Questions: q}
	for msg.ID == 0 {
		msg.ID = uint16(atomic.AddUint32(&r.qid, 1))
	}

	r.lk.Lock()

	mq := &mquery{
		result: result,
		err:    make(chan error, 1),
	}
	r.queries[msg.ID] = mq

	err = r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)
	if err != nil {
		delete(r.queries, msg.ID)
	}

	r.lk.Unlock()
	if err != nil {
		return err
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-mq.err:
	}

	r.lk.Lock()
	delete(r.queries, msg.ID)
	msg.Questions = nil
	r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)
	r.lk.Unlock()
	mq.wait.Wait()

	return err
}

// QueryOne does a one shot query
func (r *MResolver) QueryOne(ctx context.Context, q []dns.Question) ([]*dns.Record, error) {
	var result []*dns.Record
	var t *time.Timer

	tmo, cancel := context.WithTimeout(ctx, 3*time.Second)

	err := r.Query(tmo, q, func(iface string, a []*dns.Record) error {
		result = dns.Merge(result, a)
		if len(a) > 0 {
			if t == nil {
				t = time.AfterFunc(200*time.Millisecond, cancel)
			} else {
				t.Reset(200 * time.Millisecond)
			}
		}

		return nil
	})

	cancel()

	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	return result, nil
}

// Announce announces records for a name, returning when either the context is canceled or an error occurs
// (including conflict)
func (r *MResolver) Announce(ctx context.Context, names OwnerNames) error {
	id := uint16(atomic.AddUint32(&r.qid, 1))
	errc := make(chan error, 1)

	r.lk.Lock()
	r.owners[id] = errc
	r.lk.Unlock()

	defer func() {
		r.lk.Lock()
		delete(r.owners, id)
		r.lk.Unlock()
	}()

	msg := &dns.Message{ID: id, TC: true, Opcode: dns.Update}
	for _, owner := range names {
		for iface := range owner.RRSets {
			msg.Authority = []*dns.Record{
				&dns.Record{
					H: dns.NewMDNSHeader(nil, dns.TXTType, dns.NoneClass, 0, false),
					D: &dns.TXTRecord{Text: []string{iface}},
				},
			}
			msg.Answers = owner.RRSets.Records(iface)

			if err := r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize); err != nil {
				return err
			}
		}
	}
	msg.TC = false
	msg.Authority = nil
	msg.Answers = nil
	if err := r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize); err != nil {
		return err
	}

	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errc:
	}

	msg.QR = true
	r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)

	return err
}
