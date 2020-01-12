package ns

import (
	"context"
	"errors"
	"net"

	"tessier-ashpool.net/dns"
)

func (s *Server) query(ctx context.Context, msg *dns.Message, from net.Addr, zone *Zone) error {
	var err error
	q := msg.Questions[0]

	// XXX access control for recursive queries

	msg.RA = (s.res != nil)
	msg.AA = !zone.Hint()

	// try our own authority first
	msg.Answers, msg.Authority, err = zone.Lookup(
		s.conn.Interface,
		q.QName,
		q.QType,
		q.QClass,
	)

	if err == nil && len(msg.Answers) == 0 && msg.RD && msg.RA {
		// go ahead and recurse if this is a hint zone or we have a delegation
		if zone.Hint() || len(msg.Authority) > 0 {
			msg.AA = false
			msg.Authority = nil
			msg.Answers, err = s.res.Resolve(
				ctx,
				s.conn.Interface,
				q.QName,
				q.QType,
				q.QClass,
			)
		}
	}

	if msg.AA && len(msg.Authority) == 0 && errors.Is(err, dns.NXDomain) {
		soa := zone.SOA()
		if soa != nil {
			msg.Authority = []*dns.Record{soa}
		}
	}

	if err == nil {
		// fill in additionals
		s.zones.Additional(msg, s.conn.Interface, q.QClass)
	}
	answer(s.conn, err, msg, from)

	return nil
}
