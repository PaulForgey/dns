package ns

import (
	"context"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func (s *Server) update(ctx context.Context, msg *dns.Message, from net.Addr, zone *Zone) {
	q := msg.Questions[0]
	if q.QType != dns.SOAType {
		answer(s.conn, dns.FormError, true, msg, from)
		return
	}
	if !q.QClass.Asks(zone.Class()) {
		s.logger.Printf("%v: update qclass %v, zone is %v", zone.Name(), q.QClass, zone.Class())
		answer(s.conn, dns.Refused, true, msg, from)
		return
	}

	if zone.Primary != "" {
		// forward the update query to the primary ns
		r, err := resolver.NewResolverClient(nil, "udp", zone.Primary, nil, false)
		if err != nil {
			s.logger.Printf("%v: cannot create resolver to primary: %v", zone.Name(), err)
			answer(s.conn, dns.ServerFailure, true, msg, from)
			return
		}
		go func() {
			msg, err := r.Transact(ctx, nil, msg)
			r.Close()
			answer(s.conn, err, false, msg, from)
		}()
		return
	}

	zone.EnterUpdateFence()
	updated, err := zone.Update(s.conn.Interface, msg.Answers, msg.Authority)
	zone.LeaveUpdateFence()
	answer(s.conn, err, true, msg, from)

	if updated {
		zone.Notify()
	}
}
