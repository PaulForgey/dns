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
// It is safe and possible, although not beneficial, to run multiple ServeMDNS routines on the same instance.
// It is also possible to run the same zones between Serve and ServeMDNS
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
			now := time.Now()
			s.mdnsEnter(now, iface, msg.Answers)
			s.mdnsEnter(now, iface, msg.Additional)
		} else if msg.ID != 0 && len(msg.Questions) == 1 {
			// legacy unicast query
			q := msg.Questions[0]
			z := s.zones.Find(q.Name())
			if z != nil {
				msg.QR = true
				response, _, err := z.MLookup(iface, true, q.Name(), q.Type(), q.Class())
				if err != nil && !errors.Is(err, dns.NXDomain) {
					s.logger.Printf("mdns lookup error %s:%v %v %v: %v",
						iface, q.Name(), q.Class(), q.Type(), err)
					continue
				}
				if len(response) == 0 {
					continue
				}

				msg.Answers = nil
				msg.Authority = nil
				msg.Additional = nil
				for _, r := range response {
					// sanitize records for legacy query:
					// - cap TTL to 10 seconds
					// - do not return mdns specifics in header format
					ttl := r.H.TTL()
					if ttl > time.Second*10 {
						ttl = time.Second * 10
					}
					msg.Answers = append(msg.Answers,
						&dns.Record{
							H: dns.NewHeader(
								r.H.Name(),
								r.H.Type(),
								r.H.Class(),
								r.H.TTL(),
							),
							D: r.D,
						},
					)
				}

				s.zones.Additional(true, iface, msg)
				s.conn.WriteTo(msg, iface, from, messageSize(s.conn, msg))
			}
		} else {
			// mcast question
			var immediate, delayed []*dns.Record
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

				response, _, err := z.MLookup(iface, true, q.Name(), q.Type(), q.Class())
				if err != nil {
					s.logger.Printf("mdns lookup error %s:%v %v %v: %v",
						iface, q.Name(), q.Class(), q.Type(), err)
					continue
				}

				response = purgeKnownAnswers(response, msg.Answers)

				if q.(*dns.MDNSQuestion).QU() { // answer QU immediately
					immediate = append(immediate, response...)
				} else {
					delayed = append(delayed, response...)
				}
			}

			if len(immediate) > 0 {
				s.respond(iface, from, immediate)
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
			s.logger.Printf("%v:%s: error entering cache records: %v", z.Name(), iface, err)
		}
	}
}

func (s *Server) respond(iface string, to net.Addr, response []*dns.Record) error {
	msg := &dns.Message{QR: true, Answers: response}
	s.zones.Additional(true, iface, msg)
	return s.conn.WriteTo(msg, iface, to, 0 /*ignored*/)
}
