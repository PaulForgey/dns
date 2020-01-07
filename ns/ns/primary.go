package main

import (
	"context"
	"net"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func notify(ctx context.Context, soa *dns.Record, ip net.IP) bool {
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{Port: 53, IP: ip})
	if err != nil {
		logger.Printf("%v: cannot create udp socket against %v: %v", soa.RecordHeader.Name, ip, err)
		return false
	}
	conn := dnsconn.NewConnection(c, "udp")
	defer conn.Close()

	msg := &dns.Message{
		Opcode: dns.Notify,
		Questions: []*dns.Question{
			&dns.Question{
				QName:  soa.RecordHeader.Name,
				QType:  dns.SOAType,
				QClass: soa.Class(),
			},
		},
		Answers: []*dns.Record{soa},
	}
	err = conn.WriteTo(msg, nil, dnsconn.MinMessageSize)
	if err != nil {
		logger.Printf("%v: cannot send NOTIFY to %v: %v", soa.RecordHeader.Name, ip, err)
		return false
	}
	to, cancel := context.WithTimeout(ctx, time.Second*10)
	msg, _, err = conn.ReadFromIf(to, func(m *dns.Message) bool {
		return m.QR && m.ID == msg.ID
	})
	cancel()
	if err == nil && msg.RCode != dns.NoError {
		err = msg.RCode
	}
	if err != nil {
		logger.Printf("%v: NOTIFY response from %v: %v", soa.RecordHeader.Name, ip, err)
		return false
	}

	logger.Printf("%v: sent NOTIFY to %v", soa.RecordHeader.Name, ip)
	return true
}

func primaryZone(ctx context.Context, conf *Zone, zone *ns.Zone, r *resolver.Resolver) {
	var err error

	err = loadZone(zone.Zone, conf)
	if err != nil {
		logger.Fatalf("%v: cannot load zone: %v", zone.Name(), err)
	}

	for err == nil {
		soa := zone.SOA()
		if soa != nil && r != nil {
			ns, _, _ := zone.Lookup("", zone.Name(), dns.NSType, soa.Class())
			if len(ns) > 0 {
				for _, n := range ns {
					name := n.RecordData.(dns.NSRecordType).NS()
					if name.Equal(soa.RecordData.(*dns.SOARecord).MName) {
						// primary NS should be in the SOA, and if it matches, assume it is us
						continue
					}
					ips, err := r.ResolveIP(ctx, "", name, soa.Class())
					if len(ips) == 0 {
						logger.Printf(
							"%v: NS %v has no suitable IP records: %v",
							zone.Name(),
							name,
							err,
						)
					} else {
						for _, ip := range ips {
							if notify(ctx, soa, ip.IP()) {
								break
							}
						}
					}
				}
			} else {
				logger.Printf("%v: zone has no NS records", zone.Name())
			}
		}

		select {
		case <-ctx.Done():
			err = ctx.Err()

		case <-zone.C:
			err = loadZone(zone.Zone, conf)
		}
	}

	logger.Printf("%v: zone routine exiting: %v", zone.Name(), err)
}
