package main

import (
	"context"
	"io"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func transfer(ctx context.Context, zone *Zone, z *ns.Zone, soa *dns.Record, rrclass dns.RRClass) error {
	r, err := resolver.NewResolverClient(nil, "tcp", zone.Primary, nil, false)
	if err != nil {
		return err
	}
	defer r.Close()

	msg := &dns.Message{
		Opcode: dns.StandardQuery,
	}

	if zone.Incremental && soa != nil {
		msg.Questions = []dns.Question{dns.NewDNSQuestion(z.Name(), dns.IXFRType, rrclass)}
		msg.Authority = []*dns.Record{soa}
	} else {
		msg.Questions = []dns.Question{dns.NewDNSQuestion(z.Name(), dns.AXFRType, rrclass)}
	}

	tctx, cancel := context.WithTimeout(ctx, time.Minute)
	msg, err = r.Transact(tctx, nil, msg)
	cancel()
	if err != nil {
		return err
	}

	records := msg.Answers

	err = z.Xfer(zone.Incremental, func() (*dns.Record, error) {
		if len(records) == 0 {
			tctx, cancel := context.WithTimeout(ctx, time.Minute)
			msg, err := r.Receive(tctx, msg.ID)
			cancel()
			if err != nil {
				return nil, err
			}

			records = msg.Answers
			if len(records) == 0 {
				return nil, io.ErrUnexpectedEOF
			}
		}

		r := records[0]
		records = records[1:]
		return r, nil
	})
	if err != nil {
		return err
	}

	logger.Printf("%v: successfully transferred zone from %s", z.Name(), zone.Primary)
	return zone.save()
}

func pollSecondary(ctx context.Context, zone *Zone, z *ns.Zone, r *resolver.Resolver) (bool, time.Duration) {
	var refresh, retry time.Duration
	var serial uint32
	var rsoa *dns.Record

	rrclass := zone.Class
	if rrclass == 0 {
		rrclass = dns.INClass
	}

	soa := z.SOA()
	if soa == nil {
		// defaults until we can query SOA
		refresh = time.Hour * 24
		retry = time.Hour * 2
	} else {
		rr := soa.D.(*dns.SOARecord)
		refresh = rr.Refresh
		retry = rr.Retry
		serial = rr.Serial
	}

	a, _, _, aa, err := r.Query(ctx, "", z.Name(), dns.SOAType, rrclass)
	if err != nil {
		logger.Printf(
			"%v: error connecting to %s: %v. Will retry in %v",
			z.Name(),
			zone.Primary,
			err,
			retry,
		)
		return false, retry
	}
	if !aa {
		logger.Printf(
			"%v: answer from %s is not authoritative. Will retry in %v",
			z.Name(),
			zone.Primary,
			retry,
		)
		return false, retry
	}
	for _, r := range a {
		var ok bool
		if _, ok = r.D.(*dns.SOARecord); ok {
			rsoa = r
			break
		}
	}
	if rsoa == nil {
		logger.Printf(
			"%v: answer from %s did not return SOA? Will retry in %v",
			z.Name(),
			zone.Primary,
			retry,
		)
		return false, retry
	}
	if serial != rsoa.D.(*dns.SOARecord).Serial {
		err := transfer(ctx, zone, z, soa, rrclass)
		if err != nil {
			logger.Printf(
				"%v: error transferring from %s: %v. Will retry in %v",
				z.Name(),
				zone.Primary,
				err,
				retry,
			)
			return false, retry
		}
	}
	return true, refresh
}

func (zone *Zone) secondaryZone(zones *ns.Zones, res *resolver.Resolver) {
	ctx := zone.ctx
	z := zone.zone
	live := false

	r, err := resolver.NewResolverClient(nil, "udp", zone.Primary, nil, false)
	if err != nil {
		logger.Fatalf("%v: cannot create resolver against %s: %v", z.Name(), zone.Primary, err)
	}
	defer r.Close()

	// try to load from cache if we have it
	if err = zone.load(); err == nil {
		zones.Insert(z, true)
		live = true
	}
	if !live {
		logger.Printf(
			"%v: offline: %v: will transfer from primary @ %v",
			z.Name(),
			err,
			zone.Primary,
		)
	}

	success := time.Now()
	expire := time.Hour * 1000

	err = nil
	for err == nil {
		now := time.Now()
		if now.Sub(success) > expire {
			logger.Printf(
				"%v: offline: successful refresh beyond expire time of %v",
				z.Name(),
				expire,
			)
			if live {
				zones.Offline(z)
				live = false
			}
		}

		ok, refresh := pollSecondary(ctx, zone, z, r)
		if ok {
			if soa := z.SOA(); soa != nil {
				expire = soa.D.(*dns.SOARecord).Expire
			}
			// fat and happy
			success = time.Now()
			if !live {
				logger.Printf("%v: online", z.Name())
				zones.Insert(z, true)
				live = true
			}
		}

		rt := time.NewTimer(refresh)
		trigger := false
		reload := &Delay{}

		for !trigger && err == nil {
			select {
			case <-z.ReloadC():
				reload.Start()

			case <-rt.C:
				trigger = true

			case <-reload.Fire():
				reload.Reset()
				trigger = true

			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		rt.Stop()
		reload.Stop()
	}

	logger.Printf("%v: zone routine exiting: %v", z.Name(), err)
}
