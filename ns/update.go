package ns

import (
	"context"
	"fmt"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func (s *Server) update(ctx context.Context, iface string, msg *dns.Message, from net.Addr, zone *Zone) {
	q := msg.Questions[0]
	if q.Type() != dns.SOAType {
		s.answer(fmt.Errorf("%w: qtype is %v, not SOA", dns.FormError, q.Type()), true, msg, from)
		return
	}
	if !q.Class().Asks(zone.Class()) {
		s.answer(
			fmt.Errorf(
				"%w: %v update qclass is %v but zone is %v",
				dns.Refused,
				zone.Name(),
				q.Class(),
				zone.Class(),
			),
			true,
			msg,
			from,
		)
		return
	}

	if zone.Primary != "" {
		// forward the update query to the primary ns
		r, err := resolver.NewResolverClient(nil, s.conn.Network(), zone.Primary, nil, false)
		if err != nil {
			s.answer(
				fmt.Errorf(
					"%w: cannot create resolver to %v: %v",
					dns.ServerFailure,
					zone.Primary,
					err,
				),
				true,
				msg,
				from,
			)
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
