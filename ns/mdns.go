package ns

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

type flowTable struct {
	sync.Mutex
	flows map[string]*flow
}

type flow struct {
	t        *time.Timer   // expiration time of flow, at which delayed response is sent
	response []*dns.Record // proposed answer set to be whacked down as known answers come in
}

func purgeKnownAnswers(response, answers []*dns.Record) []*dns.Record {
	var updated []*dns.Record
	for _, r := range response {
		found := false
		for _, a := range answers {
			if r.Equal(a) && a.H.TTL() >= (r.H.TTL()>>1) {
				found = true
				break
			}
		}
		if !found {
			updated = append(updated, r)
		}
	}
	return updated
}

func flowKey(iface string, from net.Addr) string {
	return iface + from.String()
}

func (t *flowTable) updateFlow(key string, d time.Duration, answers []*dns.Record) {
	t.Lock()
	f, ok := t.flows[key]
	if ok {
		if !f.t.Stop() {
			// raced expiration, let it expire
			t.Unlock()
			return
		}
		f.response = purgeKnownAnswers(f.response, answers)
		f.t.Reset(d)
	}
	t.Unlock()
}

func (t *flowTable) createFlow(key string, d time.Duration, response []*dns.Record, expire func(f *flow)) {
	t.Lock()
	f := &flow{
		response: response,
	}
	f.t = time.AfterFunc(d, func() {
		expire(f)

		t.Lock()
		// remove (if not since superceded)
		v, ok := t.flows[key]
		if ok && v == f {
			delete(t.flows, key)
		}
		t.Unlock()
	})

	t.flows[key] = f // create or supercede flow
	t.Unlock()
}

// ServeMDNS runs a multicast server until the context is canceled.
// Running multiple ServerMDNS routines on the same Server instance will not crash, but it will not behave optimally.
// It is possible to run the same zones between Serve and ServeMDNS
func (s *Server) ServeMDNS(ctx context.Context) error {
	var flows flowTable

	if s.conn == nil {
		return ErrNoConnection
	}

	for {
		msg, iface, from, err := s.conn.ReadFromIf(ctx, func(m *dns.Message) bool {
			return m.Opcode == dns.StandardQuery
		})
		if err != nil {
			return err
		}

		if msg.QR {
			// answer
			if msg.ClientPort {
				s.logger.Printf("%s: mdns response from invalid source %v", iface, from)
				continue
			}

			now := time.Now()
			s.mdnsEnter(now, iface, msg.Answers)
			s.mdnsEnter(now, iface, msg.Additional)
		} else if msg.ClientPort && len(msg.Questions) == 1 {
			// legacy unicast query
			q := msg.Questions[0]
			z := s.zones.Find(q.Name())
			if z != nil {
				msg.QR = true
				a, ex, err := z.MLookup(iface, resolver.InAuth, q.Name(), q.Type(), q.Class())
				if err != nil {
					s.logger.Printf("%s: mdns lookup error %v %v %v: %v",
						iface, q.Name(), q.Class(), q.Type(), err)
					continue
				}
				if len(a) == 0 && len(ex) == 0 {
					continue
				}

				msg.Answers = make([]*dns.Record, 0, len(a)+len(ex))
				msg.Authority = nil
				msg.Additional = nil
				for n, r := range append(a, ex...) {
					// sanitize records for legacy query:
					// - cap TTL to 10 seconds
					// - do not return mdns specifics in header format
					ttl := r.H.TTL()
					if ttl > time.Second*10 {
						ttl = time.Second * 10
					}
					msg.Answers[n] = &dns.Record{
						H: dns.NewHeader(
							r.H.Name(),
							r.H.Type(),
							r.H.Class(),
							r.H.TTL(),
						),
						D: r.D,
					}
				}

				s.zones.Additional(true, iface, msg)
				s.conn.WriteTo(msg, iface, from, messageSize(s.conn, msg))
			}
		} else {
			// mcast question
			var unicast, exclusive, delayed []*dns.Record
			var delay time.Duration

			key := flowKey(iface, from)
			if msg.TC {
				delay = 400 * time.Millisecond
			} else {
				delay = 20 * time.Millisecond
			}
			delay += time.Duration((rand.Int() % 100)) * time.Millisecond

			if len(msg.Questions) == 0 {
				// continuation of known answers, update the flow and we're done
				flows.updateFlow(key, delay, msg.Answers)
				continue
			}

			for _, q := range msg.Questions {
				z := s.zones.Find(q.Name())
				if z == nil {
					continue // ignore zones we don't serve
				}

				d, e, err := z.MLookup(iface, resolver.InAuth, q.Name(), q.Type(), q.Class())
				if err != nil {
					s.logger.Printf("%s: mdns lookup error %v %v %v: %v",
						iface, q.Name(), q.Class(), q.Type(), err)
					continue
				}

				d = purgeKnownAnswers(d, msg.Answers)
				e = purgeKnownAnswers(e, msg.Answers)

				if q.(*dns.MDNSQuestion).QU() {
					unicast = append(unicast, d...)
					unicast = append(unicast, e...)
				} else {
					exclusive = append(exclusive, e...)
					delayed = append(delayed, d...)
				}
			}

			if len(unicast) > 0 {
				s.respond(iface, from, unicast)
			}
			if len(exclusive) > 0 {
				s.respond(iface, nil, exclusive)
			}
			if len(delayed) > 0 {
				flows.createFlow(key, delay, delayed, func(f *flow) {
					s.respond(iface, nil, f.response)
				})
			}
		}
	}

	return nil // unreached
}

func (s *Server) mdnsEnter(now time.Time, iface string, records []*dns.Record) {
	zones := make(map[resolver.ZoneAuthority][]*dns.Record)
	for _, r := range records {
		z := s.zones.Find(r.H.Name())
		if z != nil {
			// mDNS specific use of NSEC record to indicate a negative response
			if r.Type() == dns.NSECType && r.D != nil {
				if nsec := r.D.(*dns.NSECRecord); nsec.Next.Equal(r.Name()) {
					neg := make([]*dns.Record, 0)
					for t := nsec.Types.Next(dns.InvalidType); t != dns.InvalidType; t = nsec.Types.Next(t) {
						neg = append(neg, &dns.Record{
							dns.NewMDNSHeader(r.Name(), t, r.Class(), r.H.TTL(), true),
							nil,
						})
					}
					s.mdnsEnter(now, iface, neg)
					continue
				}
			}
			rr, ok := zones[z]
			if !ok {
				zones[z] = []*dns.Record{r}
			} else {
				zones[z] = append(rr, r)
			}
		}
		// else silently ignore records out of our zones
	}
	for z, rr := range zones {
		err := z.Enter(now, iface, rr)
		if err != nil {
			s.logger.Printf("%s: error entering cache records in %v: %v", iface, z.Name(), err)
		}
	}
}

func (s *Server) respond(iface string, to net.Addr, response []*dns.Record) error {
	msg := &dns.Message{QR: true, Answers: response}
	s.zones.Additional(true, iface, msg)
	return s.conn.WriteTo(msg, iface, to, 0)
}

// Query immediately sends the requested query along with known answers.
// This is not the end user interface to use to discover records. Use PersistentQuery for this purpose.
func (s *Server) Query(iface string, questions []dns.Question) error {
	msg := &dns.Message{}

	for _, q := range questions {
		auth := s.zones.Find(q.Name())
		if auth == nil {
			continue
		}

		msg.Questions = append(msg.Questions, q)

		a, ex, err := auth.MLookup(iface, resolver.InCache, q.Name(), q.Type(), q.Class())
		if err != nil {
			return err
		}

		for _, r := range a {
			if r.D != nil && r.H.Fresh() {
				msg.Answers = append(msg.Answers, r)
			}
		}
		for _, r := range ex {
			if r.D != nil && r.H.Fresh() {
				msg.Answers = append(msg.Answers, r)
			}
		}
	}

	err := s.conn.WriteTo(msg, iface, nil, 0)
	var t *dns.Truncated
	if errors.As(err, &t) && t.Section == 0 && len(msg.Questions) > 1 {
		ql := len(msg.Questions) >> 1
		if err := s.Query(iface, msg.Questions[:ql]); err != nil {
			return err
		}
		if err := s.Query(iface, msg.Questions[ql:]); err != nil {
			return err
		}
	}
	return err
}
