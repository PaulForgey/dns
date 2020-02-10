package resolver

import (
	"context"
	"errors"
	"io"
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
	result func([]*dns.Record) error
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
			r.lk.Unlock()
			if ok {
				if err := qr.result(msg.Answers); err != nil {
					qr.err <- err
					r.lk.Lock()
					delete(r.queries, msg.ID)
					r.lk.Unlock()
				}
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

// Query runs a persistent query asking q until ctx is done
func (r *MResolver) Query(ctx context.Context, q []dns.Question, result func([]*dns.Record) error) error {
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

	return err
}

// QueryOne does a one shot query
func (r *MResolver) QueryOne(ctx context.Context, q []dns.Question) ([]*dns.Record, error) {
	var result []*dns.Record

	tmo, cancel := context.WithTimeout(ctx, 3*time.Second)

	err := r.Query(tmo, q, func(a []*dns.Record) error {
		result = dns.Merge(result, a)
		if len(result) > 0 {
			return io.EOF
		}
		return nil
	})
	cancel()
	if errors.Is(err, io.EOF) {
		err = nil
	}

	return result, err
}
