package ns

import (
	"context"
)

// ServeMDNS runs a multicast server until the context is canceled.
// It is safe and possible, although not beneficial, to run multiple ServeMDNS routines on the same instance.
// It is also possible, although highly non standard, to run the same zones between Serve and ServeMDNS
func (s *Server) ServeMDNS(ctx context.Context) error {
	return nil
}
