package ns

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
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
					s.logger.Printf("%s: mdns lookup error %v: %v", iface, q, err)
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
					// - do not return NSEC
					if r.Type() == dns.NSECType {
						continue
					}

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
					s.logger.Printf("%s: mdns lookup error %v: %v", iface, q, err)
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

// PersistentQuery starts a persistent query q until ctx is canceled
func (s *Server) PersistentQuery(ctx context.Context, q dns.Question) error {
	var idle *time.Timer
	var err error

	backoff := time.Second
	requery := false
	first := true

	auth := s.zones.Find(q.Name())
	if auth == nil {
		return dns.NXDomain
	}

	s.logger.Printf("%v (%s): persistent query %v", s, s.conn.Network(), q)

	for err == nil {
		var rr []*dns.Record

		oneEmpty := false
		err = dnsconn.EachIface(func(iface string) error {
			var a, ex []*dns.Record

			a, ex, err = auth.MLookup(iface, resolver.InAny, q.Name(), q.Type(), q.Class())
			if err != nil {
				return err
			}

			a = append(a, ex...)
			if len(a) == 0 {
				oneEmpty = true
			} else {
				rr = append(rr, a...)
			}
			return nil
		})

		// refresh at idle backoff or half ttl, whichever is sooner
		refresh := time.Hour
		if oneEmpty {
			refresh = backoff
		} else {
			for _, r := range rr {
				if !dns.CacheFlush(r.H) {
					refresh = backoff
					break
				}
			}
			if !requery {
				for _, r := range rr {
					httl := r.H.OriginalTTL() >> 1
					if httl < r.H.TTL() {
						httl -= (r.H.OriginalTTL() - r.H.TTL())
					} else {
						httl = time.Second
					}
					if refresh > httl {
						refresh = httl
					}
				}
			}
		}

		if first && oneEmpty {
			requery = true
		}

		if requery {
			requery = false
			s.queryLock.Lock()

			queries := s.mqueries

			found := false
			for i, mq := range queries {
				if dns.Asks(mq, q) {
					// question already will be asked
					found = true
					break
				}
				if dns.Asks(q, mq) {
					// our question is more broad (wildcard over non wildcard)
					queries[i] = q
					found = true
					break
				}
			}
			if !found {
				queries = append(queries, q)
			}
			s.mqueries = queries

			if first {
				queries := s.mqueries
				s.mqueries = nil
				s.queryLock.Unlock()

				s.MQuery(queries)
			} else {
				if s.send == nil {
					s.send = time.AfterFunc(time.Second, func() {
						s.queryLock.Lock()
						s.send = nil
						queries := s.mqueries
						s.mqueries = nil
						s.queryLock.Unlock()

						s.MQuery(queries)
					})
				}

				s.queryLock.Unlock()
			}
		}

		first = false
		idle = time.NewTimer(refresh)
		if refresh == backoff && backoff < time.Hour {
			backoff <<= 1
		}

		select {
		case <-idle.C:
			requery = true
			idle = nil
		case <-ctx.Done():
			err = ctx.Err()
		}

		if idle != nil && !idle.Stop() {
			<-idle.C
		}
		idle = nil

		if mq, ok := q.(*dns.MDNSQuestion); ok {
			if mq.QU() {
				mq.SetQU(false)
			}
		}
	}

	s.logger.Printf("%v (%s): end persistent query %v: %v", s, s.conn.Network(), q, err)

	if idle != nil && !idle.Stop() {
		<-idle.C
	}

	return err
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
			s.logger.Printf("%s: error entering cache records in %v: %v", iface, z.Name(), err)
		}
	}
}

func (s *Server) respond(iface string, to net.Addr, response []*dns.Record) error {
	msg := &dns.Message{QR: true}
	for _, r := range response {
		if r.Type() != dns.NSECType {
			msg.Answers = append(msg.Answers, r)
		} else {
			msg.Additional = append(msg.Additional, r)
		}
	}
	s.zones.Additional(true, iface, msg)
	return s.conn.WriteTo(msg, iface, to, 0)
}

// MQuery immediately sends a single shot of mDNS questions.
// This is probably not the method for a typical client to use. See PersistentQuery
func (s *Server) MQuery(questions []dns.Question) error {
	return dnsconn.EachIface(func(iface string) error {
		return s.mquery(iface, questions)
	})
}

func (s *Server) mquery(iface string, questions []dns.Question) error {
	msg := &dns.Message{}

	for _, q := range questions {
		auth := s.zones.Find(q.Name())
		if auth == nil {
			continue
		}

		s.logger.Printf("%s (%v):mDNS query %v", iface, s.conn.Network(), q)

		msg.Questions = append(msg.Questions, q)

		a, ex, err := auth.MLookup(iface, resolver.InCache, q.Name(), q.Type(), q.Class())
		if err != nil {
			return err
		}

		for _, r := range a {
			if r.D != nil && (r.H.OriginalTTL()>>1) >= r.H.TTL() {
				msg.Answers = append(msg.Answers, r)
			}
		}
		for _, r := range ex {
			if r.D != nil && (r.H.OriginalTTL()>>1) >= r.H.TTL() {
				msg.Answers = append(msg.Answers, r)
			}
		}
	}

	err := s.conn.WriteTo(msg, iface, nil, 0)
	var t *dns.Truncated
	if errors.As(err, &t) && t.Section == 0 && len(msg.Questions) > 1 {
		ql := len(msg.Questions) >> 1
		if err := s.mquery(iface, msg.Questions[:ql]); err != nil {
			return err
		}
		if err := s.mquery(iface, msg.Questions[ql:]); err != nil {
			return err
		}
	}
	return err
}
