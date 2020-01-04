package ns

import (
	"context"
	"errors"
	"log"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

func sendBatch(conn *dnsconn.Connection, msg *dns.Message, to net.Addr, r []*dns.Record) error {
	msg.Answers = r
	err := answer(conn, dns.NoError, msg, to)

	var truncated *dns.Truncated
	if !conn.UDP && errors.As(err, &truncated) && len(r) > 1 {
		n := len(r) >> 1
		err = sendBatch(conn, msg, to, r[:n])
		if err == nil {
			err = sendBatch(conn, msg, to, r[n:])
		}
	}
	return err
}

func ixfr(
	ctx context.Context,
	logger *log.Logger,
	conn *dnsconn.Connection,
	msg *dns.Message,
	to net.Addr,
	zone *Zone,
) error {
	q := msg.Questions[0]

	if zone.Hint || !zone.Name.Equal(q.QName) {
		// this is not us
		return answer(conn, dns.NotAuth, msg, to)
	}

	var serial uint32
	if q.QType == dns.IXFRType {
		if len(msg.Authority) != 1 {
			return answer(conn, dns.FormError, msg, to)
		}
		s := msg.Authority[0]
		soa, ok := s.RecordData.(*dns.SOARecord)
		if !ok || !s.RecordHeader.Name.Equal(q.QName) {
			return answer(conn, dns.FormError, msg, to)
		}
		serial = soa.Serial
	}

	logger.Printf("%v: %v @%d to %v", zone.Name, q.QType, serial, to)

	msg.Authority = nil
	msg.NoTC = true
	msg.AA = true

	batch := make([]*dns.Record, 0, 64)
	err := zone.Dump(serial, conn.Interface, func(r *dns.Record) error {
		var err error
		batch = append(batch, r)
		if len(batch) == cap(batch) {
			if conn.UDP {
				err = &dns.Truncated{}
			} else {
				err = sendBatch(conn, msg, to, batch)
				batch = batch[:0]
			}
		}
		return err
	})
	if err == nil && len(batch) > 0 {
		err = sendBatch(conn, msg, to, batch)
	}

	var truncated *dns.Truncated
	if conn.UDP && errors.As(err, &truncated) {
		msg.Answers = []*dns.Record{zone.SOA()}
		logger.Printf("%v: sending @%d to %v: retry TCP", zone.Name, serial, to)
		return answer(conn, dns.NoError, msg, to)
	} else if err != nil {
		logger.Printf("%v: failed sending %v @%d to %v: %v", zone.Name, serial, to, err)
		return answer(conn, dns.ServerFailure, msg, to)
	}
	return nil
}

func notify(
	ctx context.Context,
	logger *log.Logger,
	conn *dnsconn.Connection,
	msg *dns.Message,
	to net.Addr,
	zone *Zone,
) error {
	q := msg.Questions[0]
	msg.EDNS = nil
	msg.Authority = nil
	msg.Additional = nil

	if !zone.Name.Equal(q.QName) {
		msg.Answers = nil
		return answer(conn, dns.Refused, msg, to)
	}

	if q.QType != dns.SOAType {
		return answer(conn, dns.NotImplemented, msg, to)
	}

	// XXX we have no cheap or easy way (yet) to compare rdata, so ignore the A section hint
	msg.Answers = nil

	zone.Reload()

	return answer(conn, dns.NoError, msg, to)
}
