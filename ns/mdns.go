package ns

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

type questionTable struct {
	sync.Mutex
	questions map[string]*question
}

type question struct {
	t        *time.Timer   // expiration time of question, at which delayed response is sent
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

func questionKey(iface string, from net.Addr) string {
	return iface + from.String()
}

func newQuestionTable() *questionTable {
	return &questionTable{
		questions: make(map[string]*question),
	}
}

func (t *questionTable) updateQuestion(key string, d time.Duration, answers []*dns.Record) {
	t.Lock()
	q, ok := t.questions[key]
	if ok {
		if !q.t.Stop() {
			// raced expiration, let it expire
			t.Unlock()
			return
		}
		q.response = purgeKnownAnswers(q.response, answers)
		q.t.Reset(d)
	}
	t.Unlock()
}

func (t *questionTable) createQuestion(key string, d time.Duration, response []*dns.Record, expire func(q *question)) {
	t.Lock()
	q := &question{
		response: response,
	}
	q.t = time.AfterFunc(d, func() {
		expire(q)

		t.Lock()
		// remove (if not since superceded)
		v, ok := t.questions[key]
		if ok && v == q {
			delete(t.questions, key)
		}
		t.Unlock()
	})

	t.questions[key] = q // create or supercede question
	t.Unlock()
}

// ServeMDNS runs a multicast server until the context is canceled.
// Running multiple ServerMDNS routines on the same Server instance will not crash, but it will not behave optimally.
// It is possible to run the same zones between Serve and ServeMDNS
func (s *Server) ServeMDNS(ctx context.Context) error {
	questions := newQuestionTable()

	if s.conn == nil {
		return ErrNoConnection
	}

	for {
		msg, from, err := s.conn.ReadFromIf(ctx, func(m *dns.Message) bool {
			return m.Opcode == dns.StandardQuery
		})
		if err != nil {
			return err
		}
		iface := msg.Iface

		if msg.ClientPort && len(msg.Questions) == 1 {
			// legacy unicast query
			q := msg.Questions[0]
			s.logger.Printf("%s:%v:legacy query %v", iface, from, q)
			z := s.zones.Find(q.Name())
			if z != nil {
				msg.QR = true
				a, _, err := z.MLookup(iface, resolver.InAuth, q.Name(), q.Type(), q.Class())
				if err != nil {
					s.logger.Printf("%s: mdns lookup error %v: %v", iface, q, err)
					continue
				}
				if len(a) == 0 {
					continue
				}

				// sanitize records for legacy query:
				// - cap TTL to 10 seconds
				// - do not return mdns specifics in header format

				msg.Answers = make([]*dns.Record, 0, len(a))
				msg.Authority = nil
				msg.Additional = nil

				for _, r := range a {
					ttl := r.H.TTL()
					if ttl > time.Second*10 {
						ttl = time.Second * 10
					}

					ar := &dns.Record{
						H: dns.NewHeader(r.H.Name(), r.H.Type(), r.H.Class(), ttl),
						D: r.D,
					}
					if r.Type() == dns.NSECType {
						msg.Additional = append(msg.Additional, ar)
					} else {
						msg.Answers = append(msg.Answers, ar)
					}
				}

				s.zones.Additional(true, msg)
				msg.Additional = dns.Copy(msg.Additional)

				for _, r := range msg.Additional {
					if r.H.TTL() > time.Second*10 {
						r.H.SetTTL(time.Second * 10)
					}
				}

				s.conn.WriteTo(msg, from, messageSize(s.conn, msg))
			}
		} else if msg.QR {
			// answer
			if msg.ClientPort {
				s.logger.Printf("%s: mdns response from invalid source %v", iface, from)
				continue
			}

			s.lk.Lock()
			// see if we are of interest to a probe
			dns.RecordSets(msg.Answers, func(name dns.Name, records []*dns.Record) error {
				resp, ok := s.probing[name.Key()]
				if ok {
					s.probing[name.Key()] = append(resp, msg)
				}
				return nil
			})
			s.lk.Unlock()

			now := time.Now()
			conflict, err := s.mdnsEnter(now, iface, msg.Answers)
			if err != nil {
				return err
			}
			if len(conflict) > 0 {
				dns.RecordSets(conflict, func(name dns.Name, _ []*dns.Record) error {
					nk := name.Key()
					z := s.zones.Find(name)
					if z == nil {
						// likely racing zone add/remove between mdnsEnter and here
						return nil
					}
					s.lk.Lock()
					owner, _ := s.owners[nk]
					s.lk.Unlock()
					if owner == nil {
						// no owner indcates a record we do not back down from
						// (e.g. PTR in arpa zone)
						return nil
					}

					// we seem to have received something in conflict with one of our
					// exclusive records, so put the name back into probe state
					names := make(resolver.OwnerNames)
					rrsets, err := z.Remove(name)
					if err != nil {
						s.logger.Printf("%v: error removing records: %v", name, err)
						return err
					}
					names[nk] = &resolver.OwnerName{
						Name:      name,
						Z:         z,
						RRSets:    rrsets,
						Exclusive: true,
					}
					go s.probe(ctx, names)

					return nil
				})
			}
			if _, err := s.mdnsEnter(now, iface, msg.Additional); err != nil {
				return err
			}
		} else {
			// mcast question
			var unicast, exclusive, delayed []*dns.Record
			var delay time.Duration

			if len(msg.Authority) > 0 {
				// dispatch the authority to interested names being probed (if any)
				s.lk.Lock()
				dns.RecordSets(msg.Authority, func(name dns.Name, records []*dns.Record) error {
					if resp, ok := s.probing[name.Key()]; ok {
						s.probing[name.Key()] = append(resp, msg)
					}
					return nil
				})
				s.lk.Unlock()
			}

			key := questionKey(iface, from)
			if msg.TC {
				delay = 400 * time.Millisecond
			} else {
				delay = 20 * time.Millisecond
			}
			delay += time.Duration((rand.Int() % 100)) * time.Millisecond

			if len(msg.Questions) == 0 {
				// continuation of known answers, update the flow and we're done
				questions.updateQuestion(key, delay, msg.Answers)
				continue
			}

			for _, q := range msg.Questions {
				z := s.zones.Find(q.Name())
				if z == nil {
					continue // ignore zones we don't serve
				}

				a, _, err := z.MLookup(iface, resolver.InAuth, q.Name(), q.Type(), q.Class())
				if err != nil {
					s.logger.Printf("%s: mdns lookup error %v: %v", iface, q, err)
					continue
				}
				a = purgeKnownAnswers(a, msg.Answers)

				if q.(*dns.MDNSQuestion).QU() {
					unicast = a
				} else {
					for _, r := range a {
						if dns.CacheFlush(r.H) {
							exclusive = append(exclusive, r)
						} else {
							delayed = append(delayed, r)
						}
					}
				}
			}

			if len(unicast) > 0 {
				s.respond(iface, from, unicast)
			}
			if len(exclusive) > 0 {
				s.respond(iface, nil, exclusive)
			}
			if len(delayed) > 0 {
				questions.createQuestion(key, delay, delayed, func(q *question) {
					s.respond(iface, nil, q.response)
				})
			}
		}
	}

	return nil // unreached
}

// Announce announces related records, probing exclusive ones before annoucing the set.
// If owner is nil, probing is skipped regardless (use this with caution)
func (s *Server) Announce(ctx context.Context, names resolver.OwnerNames, conflict func()) error {
	if conflict != nil {
		s.lk.Lock()
		for nk, owner := range names {
			s.logger.Printf("%v (%s): Announce", owner.Name, s.conn.Network())
			if owner.Exclusive {
				s.owners[nk] = conflict
			}
		}
		s.lk.Unlock()

		if err := s.probe(ctx, names); err != nil {
			return err
		}
	}

	return s.announce(names)
}

// SetHost sets the current announced host name
func (s *Server) SetHost(name dns.Name) {
	s.lk.Lock()
	s.host = name
	s.lk.Unlock()
}

// Host returns the current announced host name, if any. Use a persistent query for the result to track this becoming stale.
func (s *Server) Host() dns.Name {
	s.lk.Lock()
	defer s.lk.Unlock()
	return s.host
}

// Remove announced records, if we are currently answering them.
// If records are in the process of probing, the process will stop before announcing and no further action will be taken.
func (s *Server) Unannounce(names resolver.OwnerNames) error {
	// in case we are unlucky to be probing, keep these from re-appearing. probe will not move to accounce if the name
	// no longer has an owner at the time
	s.lk.Lock()
	for nk, owner := range names {
		delete(s.owners, nk)
		s.logger.Printf("%v (%s): Unannounce", owner.Name, s.conn.Network())
	}
	s.lk.Unlock()

	rrsets := make(resolver.IfaceRRSets)
	for _, owner := range names {
		nsets, err := owner.Z.Remove(owner.Name)
		if err != nil {
			s.logger.Printf("%v: error removing: %v", owner.Name, err)
			return err
		}
		for iface, records := range nsets {
			for _, r := range records {
				r.H.SetTTL(time.Second)
			}
			rrsets[iface] = dns.Merge(rrsets[iface], records)
		}
	}

	err := dnsconn.EachIface(func(iface string) error {
		records := rrsets.Records(iface)
		if len(records) == 0 {
			return nil
		}
		for _, r := range records {
			s.logger.Printf("%s: unannouncing %v", iface, r)
		}
		if err := s.respond(iface, nil, records); err != nil {
			s.logger.Printf("%s: error unannouncing: %v", iface, err)
			return err
		}
		return nil
	})

	return err
}

// PersistentQuery starts a persistent query q until ctx is canceled
func (s *Server) PersistentQuery(ctx context.Context, q dns.Question, persistent bool) error {
	var idle *time.Timer
	var err error

	backoff := time.Second
	requery := false
	first := true

	auth := s.zones.Find(q.Name())
	if auth == nil {
		return dns.NotZone
	}

	if persistent {
		s.logger.Printf("%v (%s): persistent query %v", s, s.conn.Network(), q)
	} else {
		s.logger.Printf("%v (%s); one-shot query %v", s, s.conn.Network(), q)
		backoff = 300 * time.Millisecond
	}

	for err == nil {
		var rr []*dns.Record

		exclusive := false
		empty := false

		err = dnsconn.EachIface(func(iface string) error {
			a, e, err := auth.MLookup(iface, resolver.InAny, q.Name(), q.Type(), q.Class())
			if err != nil {
				return err
			}
			exclusive = exclusive || e
			if len(a) == 0 {
				empty = true
			} else {
				rr = append(rr, a...)
			}
			return nil
		})

		refresh := backoff

		if exclusive {
			// cancel any requery if we now know they are all exclusive
			requery = requery && empty
			if persistent {
				// have answers, not shared, so requery either 1h later or half ttl
				refresh = time.Hour
			}
		}
		if first && empty {
			// requery now if we have nothing in the cache
			if len(rr) == 0 || persistent {
				// if this is a one-shot, partial answers are good answers
				requery = true
			}
		}
		if !requery {
			if !persistent {
				// if oneshot, have answers
				break
			}
			for _, r := range rr {
				// cut refresh time to half ttl if sooner than our backoff
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

		if requery {
			requery = false
			s.lk.Lock()

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

			if !persistent || (first && empty) {
				s.logger.Printf("%v (%s): sending immediate query for %v", s, s.conn.Network(), q)
				queries := s.mqueries
				s.mqueries = nil
				s.lk.Unlock()

				s.MQuery(queries)
			} else {
				if s.send == nil {
					s.send = time.AfterFunc(time.Second, func() {
						s.lk.Lock()
						s.send = nil
						queries := s.mqueries
						s.mqueries = nil
						s.lk.Unlock()

						s.MQuery(queries)
					})
				}

				s.lk.Unlock()
			}
		}

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

		if !persistent {
			break
		}
		first = false
	}

	if persistent {
		s.logger.Printf("%v (%s): end persistent query %v: %v", s, s.conn.Network(), q, err)
	}

	if idle != nil && !idle.Stop() {
		<-idle.C
	}

	return err
}

// returns true if the set of authority records in us should defer to those in them
func loseTieBreak(us, them []*dns.Record) bool {
	sort.Slice(us, func(i, j int) bool { return us[i].Less(us[j]) })
	sort.Slice(them, func(i, j int) bool { return them[i].Less(them[j]) })

	lu := len(us)
	lt := len(them)

	for i := 0; i < lu && i < lt; i++ {
		if us[i].Less(them[i]) {
			return true
		}
	}
	return lu < lt
}

func (s *Server) probe(ctx context.Context, names resolver.OwnerNames) error {
	pnames := make(resolver.OwnerNames)

	s.lk.Lock()
	for nk, owner := range names {
		if !owner.Exclusive {
			continue
		}
		_, ok := s.probing[nk]
		conflict, _ := s.owners[nk]
		if !ok && conflict != nil {
			// not already probing and the name has a conflict function
			s.probing[nk] = nil
			pnames[nk] = owner
		}
	}
	s.lk.Unlock()

	if len(pnames) == 0 {
		return nil // everyone else is already probing all these, or nothing applicable
	}

	defer func() {
		s.lk.Lock()
		for nk := range pnames {
			delete(s.probing, nk)
		}
		s.lk.Unlock()
	}()

	questions, rrset := pnames.Questions()

	if len(questions) == 0 {
		panic("no questions from non empty OwnerNames")
	}

	msgs := make(map[string]*dns.Message)

	dnsconn.EachIface(func(iface string) error {
		msgs[iface] = &dns.Message{
			NoTC:      true,
			Iface:     iface,
			Questions: questions,
			Authority: rrset.Records(iface),
		}
		return nil
	})

	sleep := func(d time.Duration) error {
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			if !t.Stop() {
				<-t.C
			}
			err := ctx.Err()
			s.logger.Printf("abandoning probe: %v", err)
			return err
		}
		return nil
	}

	// random start 0-250ms delay
	if err := sleep(time.Duration(rand.Int()%250) * time.Millisecond); err != nil {
		return err
	}

	var lost bool

	for try := 0; try < 2; try++ {
		// start clean
		lost = false
		// we are not interested in anything received before the probe attempt
		s.lk.Lock()
		for nk, owner := range pnames {
			s.probing[nk] = nil
			s.logger.Printf("%v (%s): probing", owner.Name, s.conn.Network())
		}
		s.lk.Unlock()

		var resp []*dns.Message

		// knock three times..
		for i := 0; len(resp) == 0 && i < 3; i++ {
			for iface, msg := range msgs {
				if err := s.conn.WriteTo(msg, nil, 0); err != nil {
					s.logger.Printf("%s (%s): error sending probe query: %v", iface, s.conn.Network(), err)
					return err
				}
			}

			// wait 250ms for responses
			if err := sleep(250 * time.Millisecond); err != nil {
				return err
			}

			// see what, if anything, has come in
			s.lk.Lock()
			for nk := range pnames {
				resp = append(resp, s.probing[nk]...)
			}
			s.lk.Unlock()
		}

		// iterate each interface and probe message we sent on it
		for iface, msg := range msgs {
			// look at each response received on that interface
			for _, rmsg := range resp {
				if rmsg.Iface != iface {
					continue
				}

				if rmsg.QR {
					// any answer for the name of any type or class is considered in conflict
					for _, a := range rmsg.Answers {
						for _, owner := range pnames {
							if a.Name().Equal(owner.Name) {
								lost = true
								break
							}
						}
						if lost {
							break
						}
					}
				} else {
					// tie break simultaneous probe. Both authorities include all classes.
					them := make([]*dns.Record, 0, len(rmsg.Authority))
					us := make([]*dns.Record, 0, len(msg.Authority))

					for _, owner := range pnames {
						for _, a := range rmsg.Authority {
							if a.Name().Equal(owner.Name) {
								them = append(them, a)
							}
						}
						for _, a := range msg.Authority {
							if a.Name().Equal(owner.Name) {
								us = append(us, a)
							}
						}
						if loseTieBreak(us, them) {
							// they have authority, and we must repect it
							lost = true
							break
						}

						them = them[:0]
						us = us[:0]
					}
				}
				if lost {
					break // no need to keep looking, messages per interface
				}
			}
			if lost {
				break // no need to keep looking, interfaces
			}
		}
		// win or lose, delay 1 second before taking further action
		if err := sleep(time.Second); err != nil {
			return err
		}
		if !lost {
			break // only retry a second time if there is a conflict

		}
	}

	if lost {
		var conflict func()

		// now report failure to the interested publisher of the records to resolve the conflict
		// it is up to the owner to re-attempt under a different name if it desires
		s.lk.Lock()
		for nk, owner := range pnames {
			s.logger.Printf("%v (%s): probing found conflict", owner.Name, s.conn.Network())
			if o, ok := s.owners[nk]; ok {
				if o != nil {
					conflict = o
				}
				delete(s.owners, nk)
			}
		}
		s.lk.Unlock()

		if conflict != nil {
			conflict()
		}
		return dns.YXDomain
	}

	return nil
}

func (s *Server) announce(names resolver.OwnerNames) error {
	answers := make(resolver.IfaceRRSets)

	s.lk.Lock()
	defer s.lk.Unlock()

	for nk, owner := range names {
		var nsec *dns.NSECRecord
		if owner.Exclusive {
			if o, _ := s.owners[nk]; o == nil {
				continue // skip abandoned exclusive names
			}
			nsec = &dns.NSECRecord{Next: owner.Name}
		}
		ttl := 120 * time.Second
		for iface, irecords := range owner.RRSets {
			if nsec != nil {
				for _, r := range irecords {
					ttl = r.H.TTL() // be arbitrary if not all the same
					nsec.Types.Set(r.Type())
				}
			}
			_, err := owner.Z.Enter(time.Time{}, iface, irecords)
			if err != nil {
				s.logger.Printf("%s: %v: error entering authoritative records to db: %v",
					iface, owner.Name, err)
				return err
			}
			answers.Add(iface, irecords)
		}
		if nsec != nil {
			owner.Z.Enter(time.Time{}, "", []*dns.Record{
				&dns.Record{
					H: dns.NewMDNSHeader(owner.Name, dns.NSECType, owner.RRClass, ttl, true),
					D: nsec,
				},
			})
		}
	}

	err := dnsconn.EachIface(func(iface string) error {
		records := answers.Records(iface)
		if len(records) == 0 {
			return nil
		}

		for _, r := range records {
			s.logger.Printf("%s (%s): announcing %v", iface, s.conn.Network(), r)
		}

		if err := s.respond(iface, nil, records); err != nil {
			s.logger.Printf("%s (%s): error announcing records: %v", iface, s.conn.Network(), err)
			return err
		}

		return nil
	})

	return err
}

func (s *Server) mdnsEnter(now time.Time, iface string, records []*dns.Record) ([]*dns.Record, error) {
	var conflict []*dns.Record

	err := dns.RecordSets(records, func(name dns.Name, records []*dns.Record) error {
		z := s.zones.Find(name)
		if z != nil {
			c, err := z.Enter(now, iface, records)
			if err != nil {
				s.logger.Printf("%s: error entering cache records in %v: %v", iface, z.Name(), err)
				return err
			}
			conflict = dns.Merge(conflict, c)
		}
		// else silently ignore records out of our zones
		return nil
	})

	if err != nil {
		return nil, err
	}
	return conflict, nil
}

func (s *Server) respond(iface string, to net.Addr, response []*dns.Record) error {
	msg := &dns.Message{QR: true, AA: true, Iface: iface}
	for _, r := range response {
		if r.Type() != dns.NSECType {
			msg.Answers = append(msg.Answers, r)
		} else {
			msg.Additional = append(msg.Additional, r)
		}
	}
	s.zones.Additional(true, msg)
	return s.conn.WriteTo(msg, to, 0)
}

// MQuery immediately sends a single shot of mDNS questions.
// This is probably not the method for a typical client to use. See PersistentQuery
func (s *Server) MQuery(questions []dns.Question) error {
	return dnsconn.EachIface(func(iface string) error {
		return s.mquery(iface, questions)
	})
}

func (s *Server) mquery(iface string, questions []dns.Question) error {
	msg := &dns.Message{Iface: iface}

	for _, q := range questions {
		auth := s.zones.Find(q.Name())
		if auth == nil {
			continue
		}

		s.logger.Printf("%s (%s):mDNS query %v", iface, s.conn.Network(), q)

		msg.Questions = append(msg.Questions, q)

		a, _, err := auth.MLookup(iface, resolver.InCache, q.Name(), q.Type(), q.Class())
		if err != nil {
			return err
		}

		for _, r := range a {
			if r.D != nil && (r.H.OriginalTTL()>>1) >= r.H.TTL() {
				msg.Answers = append(msg.Answers, r)
			}
		}
	}

	err := s.conn.WriteTo(msg, nil, 0)
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
