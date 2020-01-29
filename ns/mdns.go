package ns

import (
	"context"
)

// ServeMDNS runs a multicast server until the context is canceled.
// It is safe and possible, although not beneficial, to run multiple ServeMDNS routines on the same instance.
// It is also possible to run the same zones between Serve and ServeMDNS
func (s *Server) ServeMDNS(ctx context.Context) error {
	if s.conn == nil {
		return ErrNoConnection
	}
	for {
		msg, iface, from, err := s.conn.ReadFromIf(ctx, nil)
		if err != nil {
			return err
		}

		// XXX
		for _, q := range msg.Questions {
			s.logger.Printf("%s:%v: Q: %v\n", iface, from, q)
		}
		for _, a := range msg.Answers {
			s.logger.Printf("%s:%v: AN: %v\n", iface, from, a)
		}
		for _, a := range msg.Authority {
			s.logger.Printf("%s:%v: AU: %v\n", iface, from, a)
		}
		for _, a := range msg.Additional {
			s.logger.Printf("%s:%v: AD: %v\n", iface, from, a)
		}
	}

	return nil // unreached
}
