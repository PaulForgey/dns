package ns

import (
	"context"
	"errors"
	"net"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

var ErrNoSOA = errors.New("zone has no SOA record")

// SendNotify sends Notify ops to all NS records in a zone, excluding NS records having the same MName in its SOA.
// This is a best effort, and an error is returned only if something goes wrong locally to make the attempt impossible.
// If the zone has an NS record but only one matching the SOA, nothing is sent and no error is returned.
func (s *Server) SendNotify(ctx context.Context, z *Zone) error {
	if s.res == nil {
		return ErrNoResolver
	}

	r, err := resolver.NewResolverClient(nil, "udp", "", nil, false)
	if err != nil {
		return err
	}
	defer r.Close()

	soa := z.SOA()
	if soa == nil {
		return ErrNoSOA
	}
	ns, _, _ := z.Lookup("", z.Name(), dns.NSType, soa.Class())
	if len(ns) == 0 {
		return ErrNoNS
	}
	for _, n := range ns {
		rr, ok := n.D.(dns.NSRecordType)
		if !ok {
			continue
		}
		name := rr.NS()
		if name.Equal(soa.D.(*dns.SOARecord).MName) {
			continue
		}

		ips, err := s.res.ResolveIP(ctx, "", name, soa.Class())
		if len(ips) == 0 {
			if err != nil {
				return err
			}
			return ErrNoNSAddrs
		} else {
			for _, ip := range ips {
				msg := &dns.Message{
					Opcode: dns.Notify,
					Questions: []dns.Question{
						dns.NewDNSQuestion(soa.Name(), dns.SOAType, soa.Class()),
					},
					Answers: []*dns.Record{soa},
				}
				raddr := &net.UDPAddr{Port: 53, IP: ip.IP()}
				to, cancel := context.WithTimeout(ctx, time.Second*10)
				msg, err := r.Transact(to, raddr, msg)
				cancel()

				if err != nil {
					s.logger.Printf(
						"%v: error sending notify to %v (%v): %v",
						z.Name(),
						raddr,
						name,
						err,
					)
				}
			}
		}
	}

	return nil
}
