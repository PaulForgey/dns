package service

import (
	"context"
	"errors"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

var ErrSelf = errors.New("cannot determine local mdns host name")

var self dns.Name

type mdnsService struct {
	*resolver.MResolver
}

func (m *mdnsService) Lookup(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (resolver.IfaceRRSets, error) {
	answers, err := m.QueryOne(ctx, []dns.Question{dns.NewDNSQuestion(name, rrtype, rrclass)})
	if err != nil {
		return nil, err
	}
	if len(answers) == 0 {
		return nil, dns.NXDomain // force search to next provider
	}
	return answers, err
}

func (m *mdnsService) Announce(
	ctx context.Context,
	zone dns.Name, // ignored
	names resolver.OwnerNames,
) error {
	return m.MResolver.Announce(ctx, names)
}

func (m *mdnsService) Browse(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
	result func(resolver.IfaceRRSets) error,
) error {
	return m.Query(ctx, []dns.Question{dns.NewDNSQuestion(name, rrtype, rrclass)}, result)
}

func (m *mdnsService) Self() (dns.Name, error) {
	rrsets, err := m.QueryOne(context.Background(), []dns.Question{dns.NewDNSQuestion(nil, dns.AnyType, dns.AnyClass)})
	if err != nil {
		return nil, err
	}
	for _, r := range rrsets.AllRecords() {
		if r.Type() == dns.AType || r.Type() == dns.AAAAType || r.Type() == dns.HINFOType {
			return r.Name(), nil
		}
	}
	return nil, ErrSelf
}
