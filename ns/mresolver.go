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
	lk      sync.Mutex

	allowQuery  Access
	allowUpdate Access
}

type query struct {
	ctx    context.Context
	cancel func()
}

type owner struct {
	ctx    context.Context
	cancel func()
	names  resolver.OwnerNames
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
		allowQuery:  allowQuery,
		allowUpdate: allowUpdate,
	}
}

// Serve services a connection with a client until the context is canceled or the client closes.
// Although the dns message is used as the IPC message because it is natural and convenient, the exact protocol
// specifics are private and not intended to be run over any external network transport.
func (r *MResolver) Serve(ctx context.Context) error {
	queries := make(map[uint16]*query)
	owners := make(map[uint16]*owner)
	cctx, cancel := context.WithCancel(ctx)

	defer cancel()

	for {
		msg, _, err := r.conn.ReadFromIf(cctx, nil)
		if err != nil {
			return err
		}
		iface := msg.Iface

		switch msg.Opcode {
		case dns.StandardQuery: // add or remove subscribed queries
			err = nil

			if r.allowQuery.Check(ctx, nil, msg.Iface, "") {
				go r.query(cctx, queries, msg)
			} else {
				r.respond(msg.ID, "", nil, nil, false, dns.Refused)
			}

		case dns.Update: // publish records
			if r.allowUpdate.Check(ctx, nil, iface, "") {
				err = r.update(cctx, owners, msg)
			} else {
				err = dns.Refused
			}
			r.respond(msg.ID, "", nil, nil, false, err)

		default:
			msg.QR = true
			msg.Questions = nil
			msg.RCode = dns.NotImplemented
			r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)
		}
	}
}

func (r *MResolver) query(ctx context.Context, queries map[uint16]*query, msg *dns.Message) {
	pq := queries[msg.ID]
	if pq == nil {
		if !msg.QR {
			pq = &query{}
			queries[msg.ID] = pq
		}
	} else {
		pq.cancel()
	}
	if msg.QR {
		return // QR to terminate query
	}
	pq.ctx, pq.cancel = context.WithCancel(ctx)

	if len(msg.Questions) == 0 && len(r.servers) > 0 {
		msg.Questions = []dns.Question{
			dns.NewMDNSQuestion(r.servers[0].Host(), dns.AnyType, dns.INClass, false),
		}
	}

	wg := &sync.WaitGroup{} // one-shot wait

	for _, q := range msg.Questions {
		auth := r.zones.Find(q.Name())
		if auth == nil {
			continue
		}
		z, ok := auth.(*Zone)
		if !ok {
			continue
		}

		if msg.RD {
			for _, s := range r.servers {
				go func(q dns.Question, s *Server) {
					err := s.PersistentQuery(pq.ctx, q, true)
					if err != nil {
						r.respond(msg.ID, "", nil, nil, false, err)
					}
				}(q, s)
			}

			dnsconn.EachIface(func(iface string) error {
				go func(z *Zone, q dns.Question) {
					var debounce *time.Timer
					var err error

					c := make(chan struct{})
					z.PersistentQuery(c, iface, q)
					defer z.PersistentQuery(c, "", nil)

					for err == nil {
						a, _, err := z.MLookup(iface, resolver.InAny, q.Name(), q.Type(), q.Class())
						if err != nil {
							r.logger.Printf("%s: MLookup %v: %v", iface, q, err)
							if err = r.respond(msg.ID, iface, q, nil, false, err); err != nil {
								break
							}
						}
						if err = r.respond(msg.ID, iface, q, a, true, nil); err != nil {
							break
						}

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
				}(z, q)

				return nil
			})
		} else {
			wg.Add(1)
			go func(q dns.Question) {
				wg2 := &sync.WaitGroup{}
				for _, s := range r.servers {
					wg2.Add(1)
					go func(s *Server) {
						err := s.PersistentQuery(pq.ctx, q, false)
						if err != nil {
							r.respond(msg.ID, "", nil, nil, false, err)
						}
						wg2.Done()
					}(s)
				}
				wg2.Wait()
				dnsconn.EachIface(func(iface string) error {
					a, _, err := z.MLookup(iface, resolver.InAny, q.Name(), q.Type(), q.Class())
					if err != nil {
						r.logger.Printf("%s: MLookup %v: %v", iface, q, err)
					}
					return r.respond(msg.ID, iface, q, a, true, err)
				})
				wg.Done()
			}(q)
		}
	}
	if !msg.RD {
		wg.Wait()
		// end one-shot query
		r.respond(msg.ID, "", nil, nil, false, nil)
	}
}

func (r *MResolver) respond(id uint16, iface string, q dns.Question, records []*dns.Record, tc bool, err error) error {
	r.lk.Lock()
	defer r.lk.Unlock()

	msg := &dns.Message{ID: id, Opcode: dns.StandardQuery, QR: true, TC: tc}

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
		}
		r.logger.Printf("mDNS IPC %d: %v", id, err)
	}

	return r.conn.WriteTo(msg, nil, dnsconn.MaxMessageSize)
}

func (r *MResolver) update(ctx context.Context, owners map[uint16]*owner, msg *dns.Message) error {
	var iface string

	r.lk.Lock()
	defer r.lk.Unlock()

	o, ok := owners[msg.ID]

	if msg.QR {
		// ipc client sends ID with response to unannounce
		if ok {
			delete(owners, msg.ID)
			o.cancel()
		}
		return nil
	}

	if len(msg.Authority) > 0 {
		a := msg.Authority[0]
		if txt, _ := a.D.(*dns.TXTRecord); txt != nil && len(txt.Text) > 0 {
			iface = txt.Text[0]
		} else {
			return dns.FormError
		}
	}

	if !ok {
		octx, cancel := context.WithCancel(ctx)
		o = &owner{
			ctx:    octx,
			cancel: cancel,
			names:  make(resolver.OwnerNames),
		}
		owners[msg.ID] = o
	}

	// allow an empty final message
	if len(msg.Answers) > 0 {
		err := o.names.Enter(r.zones, iface, msg.Answers)
		if err != nil && !errors.Is(err, dns.NotZone) {
			// XXX need to handle NotZone better
			return err
		}
	}

	if !msg.TC {
		for _, s := range r.servers {
			go func(s *Server) {
				var err error

				err = s.Announce(o.ctx, o.names, func() {
					r.lk.Lock()
					_, ok := owners[msg.ID]
					if ok {
						delete(owners, msg.ID)
					}
					r.lk.Unlock()
					if ok {
						o.cancel()
						r.respond(msg.ID, "", nil, nil, false, dns.YXDomain)
					}
				})
				if err != nil {
					r.respond(msg.ID, "", nil, nil, false, err)
				}
			}(s)
		}

		go func() {
			<-o.ctx.Done()
			for _, s := range r.servers {
				s.Unannounce(o.names)
			}
		}()
	}

	return nil
}
