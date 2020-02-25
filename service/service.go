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

// Hostname returns what each provider in the search list believes the hostname to be using default services
func Hostname(ctx context.Context) []string {
	return DefaultServices.Hostname()
}

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
	text map[string]string,
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

// LookupSRV performs an SRV lookup using default services
func LookupSRV(ctx context.Context, service, proto, name string) ([]*dns.SRVRecord, error) {
	return DefaultServices.LookupSRV(ctx, service, proto, name)
}

// LookupMX performs an MX lookup using default services
func LookupMX(ctx context.Context, name string) ([]*dns.MXRecord, error) {
	return DefaultServices.LookupMX(ctx, name)
}

// Locate locates a service using default services
func Locate(ctx context.Context, name, serviceType, protocol string) ([]net.Addr, map[string]string, error) {
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

// AddService adds a service to the end of the list for the domain
func (s *Services) AddService(domain dns.Name, service Service) {
	s.domains[domain.Key()] = append(s.domains[domain.Key()], service)
}

// Hostname returns what each provider in the search list believes the hostname to be
func (s *Services) Hostname() []string {
	var result []string
	for _, search := range s.Search {
		for _, service := range s.servicesForDomain(search) {
			name, err := service.Self()
			if err != nil || name == nil {
				continue
			}
			hostname := name.String()
			found := false
			for _, h := range result {
				if strings.EqualFold(h, hostname) {
					found = true
					break
				}
			}
			if !found {
				result = append(result, hostname)
			}
		}
	}
	return result
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
	text map[string]string,
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

		var textRecords []string
		if len(text) == 0 {
			textRecords = []string{"\000"}
		} else {
			for k, v := range text {
				textRecords = append(textRecords, k+"="+v)
			}
		}

		var connErr resolver.ConnectionError
		for _, service := range s.servicesForDomain(u) {
			self, err := service.Self()
			if err != nil && !errors.As(err, &connErr) {
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
					D: &dns.TXTRecord{Text: textRecords},
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
				if err != nil && !errors.As(err, &connErr) {
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
				var connErr resolver.ConnectionError
				if err != nil && !errors.Is(err, dns.NXDomain) && !errors.As(err, &connErr) {
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
