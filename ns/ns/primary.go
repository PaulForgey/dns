package main

import (
	"context"
	"net"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func notify(ctx context.Context, soa *dns.Record, ip net.IP) bool {
	r, err := resolver.NewResolverClient(nil, "udp", "", nil, false)
	if err != nil {
		logger.Printf("%v: cannot create udp socket: %v", soa.RecordHeader.Name, err)
		return false
	}
	defer r.Close()

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

	raddr := &net.UDPAddr{IP: ip, Port: 53}
	to, cancel := context.WithTimeout(ctx, time.Second*10)
	msg, err = r.Transact(to, raddr, msg)
	cancel()

	if err != nil {
		logger.Printf("%v: cannot send NOTIFY to %v: %v", soa.RecordHeader.Name, ip, err)
		return false
	}

	logger.Printf("%v: sent NOTIFY to %v", soa.RecordHeader.Name, ip)
	return true
}

func (conf *Zone) primaryZone(zones *ns.Zones) {
	var err error

	ctx := conf.ctx
	zone := conf.zone
	r := zones.R

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
			err = conf.load()
		}
	}
	logger.Printf("%v: zone routine exiting: %v", zone.Name(), err)
}
