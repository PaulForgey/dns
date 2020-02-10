package main

import (
	"context"
	"fmt"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func xfer(name dns.Name, r *resolver.Resolver) {
	var err error
	msg := &dns.Message{
		Opcode:    dns.StandardQuery,
		Questions: []dns.Question{dns.NewDNSQuestion(name, rrtype, rrclass)},
	}
	if rrtype == dns.IXFRType {
		msg.Authority = []*dns.Record{
			&dns.Record{
				H: dns.NewHeader(
					name,
					dns.SOAType,
					rrclass,
					0,
				),
				D: &dns.SOARecord{
					Serial: uint32(serial),
				},
			},
		}
	}
	msg, err = r.Transact(context.Background(), nil, msg)
	if err != nil {
		exitError(err)
	}

	if debug {
		fmt.Printf("\n;; transfer:\n")
	}

	if len(msg.Answers) > 0 {
		soa, _ := msg.Answers[0].D.(*dns.SOARecord)
		if soa != nil {
			fmt.Println(msg.Answers[0])
			msg.Answers = msg.Answers[1:]
		}

		var isoa *dns.SOARecord

		for {
			for _, record := range msg.Answers {
				fmt.Println(record)

				if record.Type() == dns.SOAType && soa != nil {
					switch rrtype {
					case dns.AXFRType:
						soa = nil

					case dns.IXFRType:
						if isoa == nil {
							isoa = record.D.(*dns.SOARecord)
							if isoa.Serial == soa.Serial {
								soa = nil
							}
						} else {
							isoa = nil
						}
					}
				}
			}
			if rrtype == dns.IXFRType && len(msg.Answers) == 0 {
				// hackish single answer SOA in response
				soa = nil
			}
			if soa == nil {
				break
			}
			msg, err = r.Receive(context.Background(), msg.ID)
			if err != nil {
				exitError(err)
			}
		}
	}
}
