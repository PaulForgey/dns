package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func transfer(ctx context.Context, conf *Zone, zone *ns.Zone, soa *dns.Record, rrclass dns.RRClass) error {
	network := conf.PrimaryNetwork
	switch network {
	case "udp4", "tcp4", "ip4":
		network = "tcp4"
	case "udp6", "tcp6", "ip6":
		network = "tcp6"
	default:
		network = "tcp"
	}

	c, err := net.Dial(network, conf.Primary)
	if err != nil {
		return err
	}
	conn := dnsconn.NewConnection(c, network)
	defer conn.Close()

	msg := &dns.Message{
		ID:     uint16(os.Getpid()),
		Opcode: dns.StandardQuery,
		EDNS: &dns.Record{
			RecordHeader: dns.RecordHeader{
				MaxMessageSize: dnsconn.MaxMessageSize,
				Version:        0,
			},
			RecordData: &dns.EDNSRecord{},
		},
	}

	if conf.Incremental && soa != nil {
		msg.Questions = []*dns.Question{
			&dns.Question{
				QName:  zone.Name,
				QType:  dns.IXFRType,
				QClass: rrclass,
			},
		}
		msg.Authority = []*dns.Record{soa}
	} else {
		msg.Questions = []*dns.Question{
			&dns.Question{
				QName:  zone.Name,
				QType:  dns.AXFRType,
				QClass: rrclass,
			},
		}
	}

	if err := conn.WriteTo(msg, nil, dnsconn.MaxMessageSize); err != nil {
		return err
	}

	var records []*dns.Record

	err = zone.Xfer(conf.Incremental, func() (*dns.Record, error) {
		if len(records) == 0 {
			tctx, cancel := context.WithTimeout(ctx, time.Minute)
			msg, _, err := conn.ReadFromIf(tctx, func(_ *dns.Message) bool {
				return true
			})
			cancel()
			if err == nil && msg.RCode != dns.NoError {
				err = msg.RCode
			}
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

	logger.Printf("%v: successfully transferred zone from %s", zone.Name, conf.Primary)

	tmpfile := fmt.Sprintf("%s-%d", conf.DbFile, os.Getpid())
	out, err := os.Create(tmpfile)
	if err != nil {
		logger.Printf(
			"%v: failed to create output db file %s: %v",
			zone.Name,
			tmpfile,
			err,
		)
		return nil // just a warning
	}

	bw := bufio.NewWriter(out)
	w := dns.NewTextWriter(bw)

	err = zone.Dump(0, "", func(r *dns.Record) error {
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
			zone.Name,
			tmpfile,
			conf.DbFile,
			err,
		)
		return nil
	}

	return nil
}

func secondaryZone(ctx context.Context, zones *ns.Zones, conf *Zone, zone *ns.Zone) {
	r, err := resolver.NewResolverClient(nil, conf.PrimaryNetwork, conf.Primary, nil)
	if err != nil {
		logger.Fatalf("%v: cannot create resolver against %s: %v", zone.Name, conf.Primary, err)
	}
	rrclass := conf.Class
	if rrclass == 0 {
		rrclass = dns.INClass
	}

	live := false

	// try to load from cache if we have it
	err = loadZone(zone.Zone, conf)
	if err == nil {
		zones.Insert(zone)
		live = true
	} else {
		logger.Printf(
			"%v: %v. Will be available once transferred from primary @ %v",
			zone.Name,
			err,
			conf.Primary,
		)
	}

	var refresh, retry, expire time.Duration
	var serial uint32

	success := time.Now()
	expire = time.Hour * 1000

	for {
		now := time.Now()
		if now.Sub(success) > expire {
			logger.Printf(
				"%v: last successful refresh beyond expire time of %v. Taking zone offline",
				zone.Name,
				expire,
			)
			if live {
				zones.Remove(zone)
				live = false
			}
		}

		var rsoa *dns.Record
		soa := zone.SOA()

		if soa == nil {
			// defaults until we can query SOA
			refresh = time.Hour * 24
			retry = time.Hour * 2
			expire = time.Hour * 1000
		} else {
			rr := soa.RecordData.(*dns.SOARecord)
			refresh = rr.Refresh
			retry = rr.Retry
			expire = rr.Expire
			serial = rr.Serial
		}

		a, _, _, aa, err := r.Query(ctx, "", zone.Name, dns.SOAType, rrclass)
		if err != nil {
			logger.Printf(
				"%v: error connecting to %s: %v. Will retry in %v",
				zone.Name,
				conf.Primary,
				err,
				retry,
			)
			time.Sleep(retry)
			continue
		}
		if !aa {
			logger.Printf(
				"%v: answer from %s is not authoritative. Will retry in %v",
				zone.Name,
				conf.Primary,
				retry,
			)
			time.Sleep(retry)
			continue
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
				zone.Name,
				conf.Primary,
				retry,
			)
			time.Sleep(retry)
			continue
		}
		if serial != rsoa.RecordData.(*dns.SOARecord).Serial {
			err := transfer(ctx, conf, zone, soa, rrclass)
			if err != nil {
				logger.Printf(
					"%v: error transferring from %s: %v. Will retry in %v",
					zone.Name,
					conf.Primary,
					err,
					retry,
				)
				time.Sleep(retry)
				continue
			}
		}

		// fat and happy
		if !live {
			zones.Insert(zone)
			live = true
		}

		// XXX INOTIFY channel in zone
		success = time.Now()
		time.Sleep(refresh)
	}
}
