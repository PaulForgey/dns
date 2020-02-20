/*
Package service provides end user interfaces for discovering, locating, and annoucing services via either
DNS or mDNS as appropriate.
*/

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

var ErrNotImplemented = errors.New("not implemented or applicable")
var ErrBadProtocol = errors.New("unknown protocol")

type Service interface {
	Lookup(ctx context.Context, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (resolver.IfaceRRSets, error)

	Announce(ctx context.Context, zone dns.Name, names resolver.OwnerNames) error

	Browse(ctx context.Context, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, result func(resolver.IfaceRRSets) error) error

	Self() (dns.Name, error)
}

type Services struct {
	Search []dns.Name // search domains in order
	Update []dns.Name // announce domains

	domains map[string][]Service
}

var DefaultServices = defaultServices()

// Lookup resolves a query using default services
func Lookup(ctx context.Context, name string, rrtype dns.RRType, rrclass dns.RRClass) (resolver.IfaceRRSets, error) {
	return DefaultServices.Lookup(ctx, name, rrtype, rrclass)
}

// Announce publishes an entry using default services
func Announce(
	ctx context.Context,
	rrclass dns.RRClass,
	name, serviceType, protocol string,
	priority, weight, port uint16,
	text string,
) error {
	return DefaultServices.Announce(ctx, rrclass, name, serviceType, protocol, priority, weight, port, text)
}

// Browse browses for available entries in the network using default services
func Browse(
	ctx context.Context,
	rrclass dns.RRClass,
	serviceType, protocol string,
	result func(resolver.IfaceRRSets) error,
) error {
	return DefaultServices.Browse(ctx, rrclass, serviceType, protocol, result)
}

// LookupAddr performs a reverse lookup using default services
func LookupAddr(ctx context.Context, addr net.IP) ([]string, error) {
	return DefaultServices.LookupAddr(ctx, addr)
}

// LookupIPAddr performs a host lookup using default services
func LookupIPAddr(ctx context.Context, host string) ([]*net.IPAddr, error) {
	return DefaultServices.LookupIPAddr(ctx, host)
}

// Locate locates a service using default services
func Locate(ctx context.Context, name, serviceType, protocol string) ([]net.Addr, []string, error) {
	return DefaultServices.Locate(ctx, name, serviceType, protocol)
}

func (s *Services) servicesForDomain(name dns.Name) []Service {
	for {
		if services, ok := s.domains[name.Key()]; ok {
			return services
		}
		if len(name) == 0 {
			break
		}
		name = name.Suffix()
	}
	return nil
}

// Lookup resolves a query
func (s *Services) Lookup(
	ctx context.Context,
	name string,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (resolver.IfaceRRSets, error) {
	dname, err := dns.NameWithString(name)
	if err != nil {
		return nil, err
	}

	try := func(dname dns.Name) (resolver.IfaceRRSets, error) {
		for _, service := range s.servicesForDomain(dname) {
			result, err := service.Lookup(ctx, dname, rrtype, rrclass)
			if err == nil {
				return result, err
			}
		}
		return nil, dns.NXDomain
	}

	if !strings.HasSuffix(name, ".") {
		for _, search := range s.Search {
			result, err := try(dname.Append(search))
			if err == nil {
				return result, err
			}
		}
	}
	return try(dname)
}

// Announce publishes an entry, blocking until ctx is canceled or an error occurs, after which
// the entries are unpublished.
func (s *Services) Announce(
	ctx context.Context,
	rrclass dns.RRClass,
	name string,
	serviceType, protocol string,
	priority, weight, port uint16,
	text string,
) error {
	var err error
	errch := make(chan error, 1)
	wg := &sync.WaitGroup{}

	actx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, u := range s.Update {
		// create the update record set for this domain
		tname, err := dns.NameWithString(fmt.Sprintf("_%s._%s.%v", serviceType, protocol, u))
		if err != nil {
			return err
		}
		sname, err := dns.NameWithString(fmt.Sprintf("%s.%v", name, tname))
		if err != nil {
			return err
		}

		for _, service := range s.servicesForDomain(u) {
			self, err := service.Self()
			if err != nil {
				return err
			}
			if len(self) == 0 {
				continue
			}

			// TTLs from RFC-6762
			names := make(resolver.OwnerNames)
			err = names.Enter(nil, "", []*dns.Record{
				&dns.Record{
					H: dns.NewMDNSHeader(sname, dns.SRVType, rrclass, 75*time.Minute, true),
					D: &dns.SRVRecord{Priority: priority, Weight: weight, Port: port, Name: self},
				},
				&dns.Record{
					H: dns.NewMDNSHeader(sname, dns.TXTType, rrclass, 75*time.Minute, true),
					D: &dns.TXTRecord{Text: []string{text}},
				},
				&dns.Record{
					H: dns.NewMDNSHeader(tname, dns.PTRType, rrclass, 75*time.Minute, false),
					D: &dns.PTRRecord{Name: sname},
				},
			})
			if err != nil {
				return err
			}

			wg.Add(1)
			go func(service Service) {
				err := service.Announce(actx, u, names)
				if err != nil {
					select {
					case errch <- err:
					default: // do not block. We will wake up on and use one arbitrarily
					}
				}
				wg.Done()
			}(service)
		}
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errch:
	}
	cancel()
	wg.Wait()

	return err
}

// Browse browses for available entries in the network.
// Browse blocks until the context is canceled, an error occcurs, or result returns an error.
func (s *Services) Browse(
	ctx context.Context,
	rrclass dns.RRClass,
	serviceType, protocol string,
	result func(resolver.IfaceRRSets) error,
) error {
	var err error
	var name dns.Name

	wg := &sync.WaitGroup{}
	errc := make(chan error, 1)
	bctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if serviceType == "" && protocol == "" {
		serviceType, protocol = "services._dns-sd", "udp"
	}

	for _, search := range s.Search {
		name, err = dns.NameWithString(fmt.Sprintf("_%s._%s.%v", serviceType, protocol, search))
		if err != nil {
			return err
		}

		for _, service := range s.servicesForDomain(name) {
			wg.Add(1)
			go func(service Service, name dns.Name) {
				err := service.Browse(bctx, name, dns.PTRType, rrclass, result)
				if err != nil && !errors.Is(err, dns.NXDomain) {
					select {
					case errc <- err:
					default: // do not block
					}
				}
				wg.Done()
			}(service, name)
		}
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case err = <-errc:
	}
	cancel()
	wg.Wait()

	return err
}
