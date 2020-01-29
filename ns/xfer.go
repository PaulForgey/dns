package ns

import (
	"context"
	"errors"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

func sendBatch(conn dnsconn.Conn, msg *dns.Message, to net.Addr, r []*dns.Record) error {
	msg.Answers = r
	msg.QR = true
	msg.RCode = dns.NoError

	msgSize := messageSize(conn, msg)
	err := conn.WriteTo(msg, "", to, msgSize)

	var truncated *dns.Truncated
	_, packet := conn.(*dnsconn.PacketConn)
	if !packet && errors.As(err, &truncated) && len(r) > 1 {
		n := len(r) >> 1
		err = sendBatch(conn, msg, to, r[:n])
		if err == nil {
			err = sendBatch(conn, msg, to, r[n:])
		}
	}
	return err
}

func (s *Server) ixfr(ctx context.Context, msg *dns.Message, to net.Addr, zone *Zone) error {
	q := msg.Questions[0]

	if zone.Hint() || !zone.Name().Equal(q.Name()) {
		// this is not us
		return s.answer(dns.NotAuth, true, msg, to)
	}

	var serial uint32
	if q.Type() == dns.IXFRType {
		if len(msg.Authority) != 1 {
			return s.answer(dns.FormError, true, msg, to)
		}
		r := msg.Authority[0]
		soa, ok := r.D.(*dns.SOARecord)
		if !ok || !r.Name().Equal(q.Name()) {
			return s.answer(dns.FormError, true, msg, to)
		}
		serial = soa.Serial
	}

	s.logger.Printf("%v: %v %v @%d to %v", zone.Name(), q.Type(), q.Class(), serial, to)

	msg.Authority = nil
	msg.Additional = nil
	msg.NoTC = true
	msg.AA = true

	batch := make([]*dns.Record, 0, 64)
	_, err := zone.Dump(serial, q.Class(), func(r *dns.Record) error {
		var err error
		batch = append(batch, r)
		if len(batch) == cap(batch) {
			if _, ok := s.conn.(*dnsconn.PacketConn); ok {
				err = &dns.Truncated{}
			} else {
				err = sendBatch(s.conn, msg, to, batch)
				batch = batch[:0]
			}
		}
		if err == nil {
			err = ctx.Err()
		}
		return err
	})
	if err == nil && len(batch) > 0 {
		err = sendBatch(s.conn, msg, to, batch)
	}

	var truncated *dns.Truncated
	_, packet := s.conn.(*dnsconn.PacketConn)
	if packet && errors.As(err, &truncated) {
		msg.TC = true
		msg.Answers = []*dns.Record{zone.SOA()}
		s.logger.Printf("%v: sending @%d to %v: retry TCP", zone.Name(), serial, to)
		return s.answer(nil, false, msg, to)
	} else if err != nil {
		s.logger.Printf("%v: failed sending @%d to %v: %v", zone.Name(), serial, to, err)
		return s.answer(err, true, msg, to)
	}
	return nil
}

func (s *Server) notify(ctx context.Context, iface string, msg *dns.Message, to net.Addr, zone *Zone) error {
	q := msg.Questions[0]
	msg.Authority = nil
	msg.Additional = nil

	if q.Type() != dns.SOAType {
		return s.answer(dns.FormError, true, msg, to)
	}

	var found bool
	for _, r := range msg.Answers {
		a, _, err := zone.Lookup(iface, r.Name(), r.Type(), r.Class())
		if err != nil {
			break
		}

		found = false
		for _, rr := range a {
			if rr.Type() == r.Type() && rr.D.Equal(r.D) {
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	if !found {
		zone.Reload()
	}

	return s.answer(nil, true, msg, to)
}
