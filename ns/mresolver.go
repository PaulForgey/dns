package ns

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

// the MResolver type provides a server for local mDNS clients and services on the host using resolver.MResolver
type MResolver struct {
	logger  *log.Logger
	conn    dnsconn.Conn
	servers []*Server
	zones   *Zones
	queries map[uint16]*query
	lk      sync.Mutex

	allowQuery  Access
	allowUpdate Access
}

type query struct {
	ctx    context.Context
	cancel func()
}

// NewMResolver creates a new resolver server
func NewMResolver(
	logger *log.Logger,
	conn dnsconn.Conn,
	servers []*Server,
	zones *Zones,
	allowQuery Access,
	allowUpdate Access,
) *MResolver {
	return &MResolver{
		logger:      logger,
		conn:        conn,
		servers:     servers,
		zones:       zones,
		queries:     make(map[uint16]*query),
		allowQuery:  allowQuery,
		allowUpdate: allowUpdate,
	}
}

// Serve services a connection with a client until the context is canceled or the client closes.
// Although the dns message is used as the IPC message because it is natural and convenient, the exact protocol
// specifics are private and not intended to be run over any external network transport.
func (r *MResolver) Serve(ctx context.Context) error {
	defer func() {
		for k, v := range r.queries {
			v.cancel()
			delete(r.queries, k)
		}
	}()

	for {
		msg, iface, _, err := r.conn.ReadFromIf(ctx, nil)
		if err != nil {
			return err
		}

		switch msg.Opcode {
		case dns.StandardQuery: // add or remove subscribed queries
			err = nil

			if r.allowQuery.Check(nil, iface, "") {
				r.query(ctx, msg)
			} else {
				err = dns.Refused
			}
			r.respond(msg.ID, "", nil, nil, err)

		case dns.Update: // publish records
			if r.allowUpdate.Check(nil, iface, "") {
			}

		default:
			msg.QR = true
			msg.Questions = nil
			msg.RCode = dns.NotImplemented
			r.conn.WriteTo(msg, "", nil, dnsconn.MaxMessageSize)
		}
	}

	return nil // unreached
}

func (r *MResolver) query(ctx context.Context, msg *dns.Message) {
	pq := r.queries[msg.ID]
	if pq == nil {
		pq = &query{}
		r.queries[msg.ID] = pq
	} else {
		pq.cancel()
	}
	pq.ctx, pq.cancel = context.WithCancel(ctx)

	for _, q := range msg.Questions {
		for _, s := range r.servers {
			go func(msg *dns.Message, q dns.Question, s *Server) {
				err := s.PersistentQuery(pq.ctx, q)
				if err != nil {
					r.respond(msg.ID, "", nil, nil, err)
				}
			}(msg, q, s)
		}
		go func(msg *dns.Message, q dns.Question) {
			c := make(chan struct{})
			auth := r.zones.Find(q.Name())
			if auth == nil {
				return
			}
			z, ok := auth.(*Zone)
			if !ok {
				return
			}
			z.PersistentQuery(c, q)
			defer z.PersistentQuery(c, nil)

			var err error
			var debounce *time.Timer

			for err == nil {
				dnsconn.EachIface(func(iface string) error {
					a, ex, err := z.MLookup(iface, resolver.InAny, q.Name(), q.Type(), q.Class())
					if err != nil {
						r.logger.Printf("%s: MLookup %v: %v", iface, q, err)
						return r.respond(msg.ID, iface, q, nil, err)
					}
					return r.respond(msg.ID, iface, q, append(a, ex...), nil)
				})

				done := false
				for !done {
					var b <-chan time.Time
					if debounce != nil {
						b = debounce.C
					}
					select {
					case <-b:
						done = true
						debounce = nil
					case <-c:
						if debounce == nil {
							debounce = time.NewTimer(time.Second)
							done = true
						}

					case <-ctx.Done():
						done = true
						err = ctx.Err()
					}
				}
			}

			if debounce != nil && !debounce.Stop() {
				<-debounce.C
			}
		}(msg, q)
	}
}

func (r *MResolver) respond(id uint16, iface string, q dns.Question, records []*dns.Record, err error) error {
	r.lk.Lock()
	defer r.lk.Unlock()

	msg := &dns.Message{ID: id, Opcode: dns.StandardQuery, QR: true}

	if q != nil {
		msg.Questions = []dns.Question{q}
	}

	for _, rr := range records {
		if rr.H.TTL() < 2*time.Second {
			continue
		}
		if nsec, _ := rr.D.(*dns.NSECRecord); nsec != nil && nsec.Next.Equal(rr.Name()) {
			msg.Additional = append(msg.Additional, rr)
		} else {
			msg.Answers = append(msg.Answers, rr)
		}
	}

	if iface != "" {
		msg.Authority = []*dns.Record{&dns.Record{
			H: dns.NewHeader(nil, dns.TXTType, dns.NoneClass, 0),
			D: &dns.TXTRecord{Text: []string{iface}},
		}}
	}
	if err != nil {
		if !errors.As(err, &msg.RCode) {
			msg.RCode = dns.ServerFailure
			r.logger.Printf("mDNS query id %d: %v", id, err)
		}
	}

	return r.conn.WriteTo(msg, "", nil, dnsconn.MaxMessageSize)
}
