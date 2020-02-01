package ns

import (
	"context"
	"errors"
	"net"

	"tessier-ashpool.net/dns"
)

func (s *Server) query(ctx context.Context, msg *dns.Message, iface string, from net.Addr, zone *Zone) error {
	var err error
	q := msg.Questions[0]

	msg.RA = (s.res != nil) && s.allowRecursion.Check(from, iface, "")
	msg.AA = !zone.Hint()

	// try our own authority first
	msg.Answers, msg.Authority, err = zone.Lookup(iface, q.Name(), q.Type(), q.Class())

	if err == nil && len(msg.Answers) == 0 && msg.RD && msg.RA {
		// go ahead and recurse if this is a hint zone or we have a delegation
		if zone.Hint() || len(msg.Authority) > 0 {
			msg.AA = false
			msg.Authority = nil
			msg.Answers, err = s.res.Resolve(ctx, iface, q.Name(), q.Type(), q.Class())
		}
	}

	if msg.AA && len(msg.Authority) == 0 && errors.Is(err, dns.NXDomain) {
		soa := zone.SOA()
		if soa != nil {
			msg.Authority = []*dns.Record{soa}
		}
	}

	// fill in additionals
	msg.Additional = nil
	if err == nil {
		s.zones.Additional(false, iface, msg)
	}

	return s.answer(err, false, msg, from)
}
