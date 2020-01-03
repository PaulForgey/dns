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

func axfr(
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
	if conn.UDP {
		// this is undefined, but respond with empty TC message
		msg.TC = true
		return answer(conn, dns.NoError, msg, to)
	}
	logger.Printf("AXFR zone %v to %v", zone.Name, to)

	msg.NoTC = true
	batch := make([]*dns.Record, 0, 64)
	err := zone.Dump(0, conn.Interface, func(r *dns.Record) error {
		var err error
		batch = append(batch, r)
		if len(batch) == cap(batch) {
			err = sendBatch(conn, msg, to, batch)
			batch = batch[:0]
		}
		return err
	})

	if err == nil && len(batch) > 0 {
		err = sendBatch(conn, msg, to, batch)
	}
	if err != nil {
		logger.Printf("failed sending zone %v to %v: %v", zone.Name, to, err)
		return answer(conn, dns.ServerFailure, msg, to)
	}
	return nil
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
	if len(msg.Authority) != 1 {
		return answer(conn, dns.FormError, msg, to)
	}
	s := msg.Authority[0]
	soa, ok := s.RecordData.(*dns.SOARecord)
	if !ok || !s.RecordHeader.Name.Equal(q.QName) {
		return answer(conn, dns.FormError, msg, to)
	}
	msg.Authority = nil

	logger.Printf("IXFR zone %v @%d to %v", zone.Name, soa.Serial, to)

	msg.NoTC = true
	batch := make([]*dns.Record, 0, 64)
	err := zone.Dump(soa.Serial, conn.Interface, func(r *dns.Record) error {
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
		logger.Printf("sending zone %v @%d to %v: retry TCP", zone.Name, soa.Serial, to)
		return answer(conn, dns.NoError, msg, to)
	} else if err != nil {
		logger.Printf("failed sending zone %v @%d to %v: %v", zone.Name, soa.Serial, to, err)
		return answer(conn, dns.ServerFailure, msg, to)
	}
	return nil
}
