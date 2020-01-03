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

		// we only do standard queries
		// XXX update
		if msg.Opcode != dns.StandardQuery {
			logger.Printf("tossing query with opcode %d from %v", msg.Opcode, from)
			continue
		}

		// should be 1 question
		if len(msg.Questions) < 1 {
			logger.Printf("tossing query with no question from %v", from)
			continue
		}

		q := msg.Questions[0]
		zone := zones.Find(q.QName)

		// zone can be nil if we are not running with a hint zone at .
		if zone == nil {
			// this also makes recursive queries impossible, so refuse the query regardless.
			answer(conn, dns.Refused, msg, from)
			continue
		}

		logger.Printf("%s:%v:%v: %v", conn.Interface, from, zone.Name, q)

		// XXX access control for zone transfers
		switch q.QType {
		case dns.AXFRType:
			axfr(ctx, logger, conn, msg, from, zone)
			continue
		case dns.IXFRType:
			ixfr(ctx, logger, conn, msg, from, zone)
			continue
		}

		// XXX access control for queries
		// XXX access control for recursive queries

		msg.RA = zone.Hint && (zones.R != nil)
		msg.AA = false
		if msg.RD && msg.RA {
			msg.Answers, err = zones.R.Resolve(
				ctx,
				conn.Interface,
				q.QName,
				q.QType,
				q.QClass,
			)
		} else {
			msg.Answers, msg.Authority, err = zone.Lookup(
				conn.Interface,
				q.QName,
				q.QType,
				q.QClass,
			)
			if len(msg.Authority) == 0 && !zone.Hint {
				msg.AA = true
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

	return conn.WriteTo(msg, to, msgSize)
}
