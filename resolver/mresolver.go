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
	}

	go func() {
		var err error
		for {
			var msg *dns.Message

			msg, _, _, err = conn.ReadFromIf(context.Background(), nil)
			if err != nil {
				break
			}

			r.lk.Lock()
			qr, ok := r.queries[msg.ID]
			if ok {
				qr.wait.Add(1)
			}
			r.lk.Unlock()
			if ok {
				var iface string

				if len(msg.Authority) > 0 {
					txt, _ := msg.Authority[0].D.(*dns.TXTRecord)
					if txt != nil {
						iface = txt.Text[0]
					}
				}

				if err := qr.result(iface, msg.Answers); err != nil {
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

	err = r.conn.WriteTo(msg, "", nil, dnsconn.MaxMessageSize)
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
	r.conn.WriteTo(msg, "", nil, dnsconn.MaxMessageSize)
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
