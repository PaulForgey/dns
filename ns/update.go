package ns

import (
	"context"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func (s *Server) update(ctx context.Context, iface string, msg *dns.Message, from net.Addr, zone *Zone) {
	q := msg.Questions[0]
	if q.Type() != dns.SOAType {
		s.answer(dns.FormError, true, msg, from)
		return
	}
	if !q.Class().Asks(zone.Class()) {
		s.logger.Printf("%v: update qclass %v, zone is %v", zone.Name(), q.Class(), zone.Class())
		s.answer(dns.Refused, true, msg, from)
		return
	}

	if zone.Primary != "" {
		// forward the update query to the primary ns
		r, err := resolver.NewResolverClient(nil, s.conn.Network(), zone.Primary, nil, false)
		if err != nil {
			s.logger.Printf("%v: cannot create resolver to primary: %v", zone.Name(), err)
			s.answer(dns.ServerFailure, true, msg, from)
			return
		}
		go func() {
			msg, err := r.Transact(ctx, nil, msg)
			r.Close()
			s.answer(err, false, msg, from)
		}()
		return
	}

	zone.EnterUpdateFence()
	updated, err := zone.Update(iface, msg.Answers, msg.Authority)
	zone.LeaveUpdateFence()
	s.answer(err, true, msg, from)

	if updated {
		zone.Notify()
	}
}
