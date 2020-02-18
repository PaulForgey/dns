package resolver

import (
	"context"
	"errors"
	"net"
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
	answers IfaceRRSets
	result  func(IfaceRRSets) error
	err     chan error
	t       *time.Timer
}

// NewMResolverClient creates a new client side IPC endpoint to talk to ns.MResolver.
// network must be stream oriented.
func NewMResolverClient(network, address string) (*MResolver, error) {
	c, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	conn := dnsconn.NewStreamConn(c, network, "")
	conn.MDNS()
	return NewMResolver(conn), nil
}

// NewMResolver creates a new client side IPC endpoint using an existing connection.
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
			o, ok := r.owners[msg.ID]
			if ok {
				if msg.RCode != dns.NoError {
					delete(r.owners, msg.ID)
					o <- msg.RCode
				} else {
					o = nil
				}
			}
			r.lk.Unlock()

			if qr != nil {
				var iface string
				if len(msg.Authority) > 0 {
					// first record denotes interface
					txt, _ := msg.Authority[0].D.(*dns.TXTRecord)
					if txt != nil {
						iface = txt.Text[0]
					}
				}

				r.lk.Lock()

				if qr.answers == nil {
					qr.answers = make(IfaceRRSets)
				}
				qr.answers.Add(iface, msg.Answers)

				if qr.t == nil {
					qr.t = time.AfterFunc(200*time.Millisecond, func() {
						r.lk.Lock()
						answers := qr.answers
						qr.answers = nil
						qr.t = nil
						r.lk.Unlock()

						if err := qr.result(answers); err != nil {
							r.lk.Lock()
							delete(r.queries, msg.ID)
							r.lk.Unlock()

							qr.err <- err
						}
					})
				}

				r.lk.Unlock()
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
func (r *MResolver) Query(ctx context.Context, q []dns.Question, result func(IfaceRRSets) error) error {
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
	if mq.t != nil {
		mq.t.Stop()
	}
	delete(r.queries, msg.ID)
	msg.Questions = nil
	msg.QR = true
	r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)
	r.lk.Unlock()

	return err
}

// QueryOne does a one shot query
var errOneShot = errors.New("once")

func (r *MResolver) QueryOne(ctx context.Context, q []dns.Question) (IfaceRRSets, error) {
	var result IfaceRRSets

	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)

	err := r.Query(qctx, q, func(answers IfaceRRSets) error {
		result = answers
		return errOneShot
	})

	cancel()

	if !errors.Is(err, errOneShot) {
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
