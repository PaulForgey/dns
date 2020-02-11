package ns

import (
	"context"
	"errors"
	"log"
	"sync"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

// the MResolver type provides a server for local mDNS clients and services on the host using resolver.MResolver
type MResolver struct {
	logger  *log.Logger
	conn    dnsconn.Conn
	servers []*Server
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
	allowQuery Access,
	allowUpdate Access,
) *MResolver {
	return &MResolver{
		logger:      logger,
		conn:        conn,
		servers:     servers,
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
			pq := r.queries[msg.ID]

			if r.allowQuery.Check(nil, iface, "") {
				if pq == nil {
					pq = &query{}
					r.queries[msg.ID] = pq
				} else {
					pq.cancel()
				}
				pq.ctx, pq.cancel = context.WithCancel(ctx)

				for _, s := range r.servers {
					for _, q := range msg.Questions {
						go func(msg *dns.Message, iface string, s *Server, q dns.Question) {
							err := s.PersistentQuery(
								pq.ctx, q,
								func(iface string, records []*dns.Record) error {
									return r.respond(msg.ID, iface, records, nil)
								})
							if err != nil {
								r.respond(msg.ID, "", nil, err)
							}
						}(msg, iface, s, q)
					}
				}
			} else {
				err = dns.Refused
			}
			r.respond(msg.ID, "", nil, err)

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

func (r *MResolver) respond(id uint16, iface string, records []*dns.Record, err error) error {
	r.lk.Lock()
	defer r.lk.Unlock()

	msg := &dns.Message{ID: id, Opcode: dns.StandardQuery, QR: true, Answers: records}

	if iface != "" {
		msg.Authority = []*dns.Record{&dns.Record{
			H: dns.NewHeader(nil, dns.TXTType, dns.NoneClass, 0),
			D: &dns.TXTRecord{Text: []string{iface}},
		}}
	}
	if err != nil {
		if !errors.As(err, &msg.RCode) {
			msg.RCode = dns.ServerFailure
			r.logger.Printf("mDNS query id %d failed: %v", id, err)
		}
	}

	return r.conn.WriteTo(msg, "", nil, dnsconn.MaxMessageSize)
}
