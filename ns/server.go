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
	logger.Printf("listening on %v", conn)

	for {
		msg, from, err := conn.ReadFromIf(ctx, func(msg *dns.Message) bool {
			return !msg.QR // only questions
		})
		if err != nil {
			logger.Printf("listener %v exiting: %v", conn, err)
			return err
		}

		// we only do standard queries
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

		logger.Printf("%v: %v", from, q)

		// XXX handle XFER, IXFR, etc.
		//     Until we do, just dumbly treat these types as normal types which we will not find.

		// XXX access control for queries

		msg.RA = (zone.R != nil)
		msg.AA = false
		if msg.RD && zone.R != nil {
			// XXX access control for recursive queries
			msg.Answers, err = zone.R.Resolve(
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

		// fill in additionals
		for _, r := range msg.Authority {
			if nrec, ok := r.RecordData.(dns.NameRecordType); ok {
				zones.Additional(msg, conn.Interface, q.QClass, nrec)
			}
		}
		for _, r := range msg.Answers {
			if nrec, ok := r.RecordData.(dns.NameRecordType); ok {
				zones.Additional(msg, conn.Interface, q.QClass, nrec)
			}
		}

		var rcode dns.RCode
		if errors.As(err, &rcode) {
			answer(conn, rcode, msg, from)
			continue
		}
		if err != nil {
			logger.Printf("Error answering %v from %v: %v", q, from, err)
			answer(conn, dns.ServerFailure, msg, from)
			continue
		}

		answer(conn, dns.NoError, msg, from)
	}

	return nil // unreached
}

func answer(conn *dnsconn.Connection, rcode dns.RCode, msg *dns.Message, to net.Addr) error {
	msg.QR = true
	msg.RCode = rcode
	return conn.WriteTo(msg, to)
}
