package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func transfer(ctx context.Context, conf *Zone, zone *ns.Zone, soa *dns.Record, rrclass dns.RRClass) error {
	r, err := resolver.NewResolverClient(nil, "tcp", conf.Primary, nil, false)
	if err != nil {
		return err
	}
	defer r.Close()

	msg := &dns.Message{
		Opcode: dns.StandardQuery,
	}

	if conf.Incremental && soa != nil {
		msg.Questions = []*dns.Question{
			&dns.Question{
				QName:  zone.Name(),
				QType:  dns.IXFRType,
				QClass: rrclass,
			},
		}
		msg.Authority = []*dns.Record{soa}
	} else {
		msg.Questions = []*dns.Question{
			&dns.Question{
				QName:  zone.Name(),
				QType:  dns.AXFRType,
				QClass: rrclass,
			},
		}
	}

	tctx, cancel := context.WithTimeout(ctx, time.Minute)
	msg, err = r.Transact(tctx, nil, msg)
	cancel()
	if err != nil {
		return err
	}

	records := msg.Answers

	err = zone.Xfer(conf.Incremental, func() (*dns.Record, error) {
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

	logger.Printf("%v: successfully transferred zone from %s", zone.Name(), conf.Primary)

	if conf.DbFile != "" {
		tmpfile := fmt.Sprintf("%s-%d", conf.DbFile, os.Getpid())
		out, err := os.Create(tmpfile)
		if err != nil {
			logger.Printf(
				"%v: failed to create output db file %s: %v",
				zone.Name(),
				tmpfile,
				err,
			)
			return nil // just a warning
		}

		bw := bufio.NewWriter(out)
		w := dns.NewTextWriter(bw)

		err = zone.Dump(0, "", dns.AnyClass, func(r *dns.Record) error {
			return w.Encode(r)
		})
		if err != nil {
			return err // more than a warning, something is wrong
		}

		if err := bw.Flush(); err != nil {
			return err
		}
		out.Close()

		err = os.Rename(tmpfile, conf.DbFile)
		if err != nil {
			logger.Printf(
				"%v: failed to rename %s->%s: %v",
				zone.Name(),
				tmpfile,
				conf.DbFile,
				err,
			)
			return nil
		}
	}

	return nil
}

func pollSecondary(ctx context.Context, conf *Zone, zone *ns.Zone, r *resolver.Resolver) (bool, time.Duration) {
	var refresh, retry time.Duration
	var serial uint32
	var rsoa *dns.Record

	rrclass := conf.Class
	if rrclass == 0 {
		rrclass = dns.INClass
	}

	soa := zone.SOA()
	if soa == nil {
		// defaults until we can query SOA
		refresh = time.Hour * 24
		retry = time.Hour * 2
	} else {
		rr := soa.RecordData.(*dns.SOARecord)
		refresh = rr.Refresh
		retry = rr.Retry
		serial = rr.Serial
	}

	a, _, _, aa, err := r.Query(ctx, "", zone.Name(), dns.SOAType, rrclass)
	if err != nil {
		logger.Printf(
			"%v: error connecting to %s: %v. Will retry in %v",
			zone.Name(),
			conf.Primary,
			err,
			retry,
		)
		return false, retry
	}
	if !aa {
		logger.Printf(
			"%v: answer from %s is not authoritative. Will retry in %v",
			zone.Name(),
			conf.Primary,
			retry,
		)
		return false, retry
	}
	for _, r := range a {
		var ok bool
		if _, ok = r.RecordData.(*dns.SOARecord); ok {
			rsoa = r
			break
		}
	}
	if rsoa == nil {
		logger.Printf(
			"%v: answer from %s did not return SOA? Will retry in %v",
			zone.Name(),
			conf.Primary,
			retry,
		)
		return false, retry
	}
	if serial != rsoa.RecordData.(*dns.SOARecord).Serial {
		err := transfer(ctx, conf, zone, soa, rrclass)
		if err != nil {
			logger.Printf(
				"%v: error transferring from %s: %v. Will retry in %v",
				zone.Name(),
				conf.Primary,
				err,
				retry,
			)
			return false, retry
		}
	}
	return true, refresh
}

func (conf *Zone) secondaryZone(zones *ns.Zones, res *resolver.Resolver) {
	ctx := conf.ctx
	zone := conf.zone
	live := false

	r, err := resolver.NewResolverClient(nil, "udp", conf.Primary, nil, false)
	if err != nil {
		logger.Fatalf("%v: cannot create resolver against %s: %v", zone.Name(), conf.Primary, err)
	}
	defer r.Close()

	// try to load from cache if we have it
	if conf.DbFile != "" {
		if err = conf.load(); err == nil {
			zones.Insert(zone, true)
			live = true
		}
	}
	if !live {
		logger.Printf(
			"%v: offline: %v: will transfer from primary @ %v",
			zone.Name(),
			err,
			conf.Primary,
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
				zone.Name(),
				expire,
			)
			if live {
				zones.Offline(zone)
				live = false
			}
		}

		ok, refresh := pollSecondary(ctx, conf, zone, r)
		if ok {
			if soa := zone.SOA(); soa != nil {
				expire = soa.RecordData.(*dns.SOARecord).Expire
			}
			// fat and happy
			success = time.Now()
			if !live {
				logger.Printf("%v: online", zone.Name())
				zones.Insert(zone, true)
				live = true
			}
		}

		rt := time.NewTimer(refresh)
		var reload *time.Timer
		var reloadC <-chan time.Time
		trigger := false

		for !trigger && err == nil {
			select {
			case <-zone.C:
				if reload != nil {
					reload.Stop()
				}
				reload = time.NewTimer(time.Duration(rand.Int()%5+5) * time.Second)
				reloadC = reload.C

			case <-rt.C:
				trigger = true
			case <-reloadC:
				trigger = true

			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		rt.Stop()
		if reload != nil {
			reload.Stop()
		}
	}

	logger.Printf("%v: zone routine exiting: %v", zone.Name(), err)
}
