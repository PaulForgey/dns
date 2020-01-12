package ns

import (
	"context"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func (s *Server) update(ctx context.Context, msg *dns.Message, from net.Addr, zone *Zone) {
	if zone.Primary != "" {
		// forward the update query to the primary ns
		r, err := resolver.NewResolverClient(nil, "udp", zone.Primary, nil, false)
		if err != nil {
			s.logger.Printf("%v: cannot create resolver to primary: %v", zone.Name(), err)
			answer(s.conn, dns.ServerFailure, msg, from)
			return
		}
		go func() {
			msg, err := r.Transact(ctx, nil, msg)
			r.Close()
			answer(s.conn, err, msg, from)
		}()
		return
	}

	updated, err := zone.Update(s.conn.Interface, msg.Answers, msg.Authority)
	answer(s.conn, err, msg, from)

	if updated {
		go func() {
			err := s.SendNotify(ctx, zone)
			if err != nil {
				s.logger.Printf("%v: failed to send notify: %v", zone.Name(), err)
			}
		}()
	}
}
