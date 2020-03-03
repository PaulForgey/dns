package ns

import (
	"context"
	"errors"
	"net"
	"runtime/trace"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func (s *Server) query(ctx context.Context, msg *dns.Message, from net.Addr, zone *Zone) error {
	var err error
	q := msg.Questions[0]

	msg.RA = (s.res != nil) && s.allowRecursion.Check(ctx, from, msg.Iface, "")
	msg.AA = !zone.Hint()

	// try our own authority first
	region := trace.StartRegion(ctx, "lookup")
	msg.Answers, msg.Authority, err = zone.Lookup(msg.Iface, q.Name(), q.Type(), q.Class())
	region.End()

	// do a limited CNAME chase if its within our zone or cache
	if q.Type() != dns.CNAMEType && len(msg.Answers) > 0 && msg.Answers[0].Type() == dns.CNAMEType {
		var a []*dns.Record
		var z resolver.ZoneAuthority
		cname := msg.Answers[0].D.(*dns.CNAMERecord).Name

		region := trace.StartRegion(ctx, "lookup:cname")
		a, z, err = resolver.ResolveCNAME(s.zones, msg.Iface, cname, q.Type(), q.Class())
		msg.Answers = append(msg.Answers, a...)
		region.End()

		if msg.RD && msg.RA && len(a) == 0 {
			// if we ran out and recursion is available, restart the query recursively
			msg.Answers = nil
		} else if z != nil {
			msg.AA = !z.Hint()
		}
	}

	if err == nil && len(msg.Answers) == 0 && msg.RD && msg.RA {
		// go ahead and recurse if this is a hint zone or we have a delegation
		if zone.Hint() || len(msg.Authority) > 0 {
			msg.AA = false
			msg.Authority = nil
			region := trace.StartRegion(ctx, "resolve")
			msg.Answers, err = s.res.Resolve(ctx, msg.Iface, q.Name(), q.Type(), q.Class())
			region.End()
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
		region := trace.StartRegion(ctx, "additional")
		s.zones.Additional(false, msg)
		region.End()
	}

	return s.answer(err, false, msg, from)
}
