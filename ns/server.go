package ns

import (
	"context"
	"errors"
	"log"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

// Serve runs a unicast server answering queries for the zone set until the context is canceled or an error occurs on the conn
func Serve(ctx context.Context, logger *log.Logger, conn *dnsconn.Connection, zones *Zones) error {
	for {
		msg, from, err := conn.ReadFromIf(ctx, func(*dns.Message) bool {
			return true // we are the only consumer
		})
		if err != nil {
			logger.Printf("listener %v exiting: %v", conn, err)
			return err
		}
		if msg.QR {
			continue // only questions
		}

		var q *dns.Question
		if len(msg.Questions) > 0 {
			q = msg.Questions[0]
		} else {
			// XXX this needs to change if we ever support an op with no Q section
			answer(conn, dns.FormError, msg, from)
			continue
		}

		logger.Printf("%s:%v:%v: %v", conn.Interface, from, msg.Opcode, q)

		switch msg.Opcode {
		// XXX update

		case dns.Notify:
			// XXX notify access control
			if zone := zones.Zone(q.QName); zone != nil {
				notify(ctx, logger, conn, msg, from, zone)
			} else {
				msg.Answers = nil
				answer(conn, dns.Refused, msg, from)
			}
			continue

		case dns.StandardQuery:
			// handled below

		default:
			answer(conn, dns.NotImplemented, msg, from)
			continue
		}

		//standard query

		// find zone for the question
		zone := zones.Find(q.QName)
		if zone == nil {
			// zone can be nil if we are not running with a hint zone at .
			// nothing else we can do without one
			answer(conn, dns.Refused, msg, from)
			continue
		}

		// XXX access control for zone transfers
		switch q.QType {
		case dns.AXFRType, dns.IXFRType:
			ixfr(ctx, logger, conn, msg, from, zone.(*Zone))
			continue
		}

		// XXX access control for queries
		// XXX access control for recursive queries

		msg.RA = (zones.R != nil)
		msg.AA = !zone.Hint()

		// try our own authority first
		msg.Answers, msg.Authority, err = zone.Lookup(
			conn.Interface,
			q.QName,
			q.QType,
			q.QClass,
		)

		if err == nil && len(msg.Answers) == 0 && msg.RD && msg.RA {
			// go ahead and recurse if this is a hint zone or we have a delegation
			if zone.Hint() || len(msg.Authority) > 0 {
				msg.AA = false
				msg.Authority = nil
				msg.Answers, err = zones.R.Resolve(
					ctx,
					conn.Interface,
					q.QName,
					q.QType,
					q.QClass,
				)
			}
		}

		if msg.AA && len(msg.Authority) == 0 && errors.Is(err, dns.NameError) {
			soa := zone.SOA()
			if soa != nil {
				msg.Authority = []*dns.Record{soa}
			}
		}

		var rcode dns.RCode
		if err == nil {
			// fill in additionals
			zones.Additional(msg, conn.Interface, q.QClass)
		} else if !errors.As(err, &rcode) {
			if err != nil {
				logger.Printf("Error answering %v from %v: %v", q, from, err)
				rcode = dns.ServerFailure
			}
		}
		answer(conn, rcode, msg, from)
	}

	return nil // unreached
}

func answer(conn *dnsconn.Connection, rcode dns.RCode, msg *dns.Message, to net.Addr) error {
	msg.QR = true
	msg.RCode = rcode

	msgSize := dnsconn.MinMessageSize

	// client's EDNS message
	if conn.UDP {
		if msg.EDNS != nil {
			msgSize = int(msg.EDNS.RecordHeader.MaxMessageSize)
			if msgSize < dnsconn.MinMessageSize {
				msgSize = dnsconn.MinMessageSize
			}

			// respond with our own
			msg.EDNS = &dns.Record{
				RecordHeader: dns.RecordHeader{
					MaxMessageSize: dnsconn.UDPMessageSize,
					Version:        0,
				},
				RecordData: &dns.EDNSRecord{},
			}
		}
	} else {
		msgSize = dnsconn.MaxMessageSize
	}

	return conn.WriteTo(msg, to, msgSize)
}
