package service

import (
	"context"
	"errors"
	"sync"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

var ErrSelf = errors.New("cannot determine local mdns host name")

const mdnsSocket = "/var/run/mDNS/mDNS-socket"

type mdnsService struct {
	sync.RWMutex
	res *resolver.MResolver
}

func (m *mdnsService) connect() (*resolver.MResolver, error) {
	var res *resolver.MResolver
	var err error

	m.RLock()
	if m.res == nil {
		m.RUnlock()
		m.Lock()
		if m.res == nil {
			res, err = resolver.NewMResolverClient("unix", mdnsSocket)
			m.res = res
		}
		m.Unlock()
	} else {
		res = m.res
		m.RUnlock()
	}
	return res, err
}

func (m *mdnsService) connErr(res *resolver.MResolver, err error) error {
	var ce resolver.ConnectionError
	if errors.As(err, &ce) {
		m.Lock()
		res.Close()
		if res == m.res {
			m.res = nil
		}
		m.Unlock()
	}
	return err
}

func (m *mdnsService) Lookup(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (resolver.IfaceRRSets, error) {
	res, err := m.connect()
	if err != nil {
		return nil, err
	}
	answers, err := res.QueryOne(ctx, []dns.Question{dns.NewDNSQuestion(name, rrtype, rrclass)})
	if err != nil {
		return nil, m.connErr(res, err)
	}
	if len(answers) == 0 {
		return nil, dns.NXDomain // force search to next provider
	}
	return answers, nil
}

func (m *mdnsService) Announce(
	ctx context.Context,
	zone dns.Name, // ignored
	names resolver.OwnerNames,
) error {
	res, err := m.connect()
	if err != nil {
		return err
	}
	return m.connErr(res, res.Announce(ctx, names))
}

func (m *mdnsService) Browse(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
	result func(resolver.IfaceRRSets) error,
) error {
	res, err := m.connect()
	if err != nil {
		return err
	}
	return m.connErr(res, res.Query(ctx, []dns.Question{dns.NewDNSQuestion(name, rrtype, rrclass)}, result))
}

func (m *mdnsService) Self() (dns.Name, error) {
	res, err := m.connect()
	if err != nil {
		return nil, err
	}
	rrsets, err := res.QueryOne(context.Background(), nil)
	if err != nil {
		return nil, m.connErr(res, err)
	}
	for _, r := range rrsets.AllRecords() {
		if r.Type() == dns.AType || r.Type() == dns.AAAAType || r.Type() == dns.HINFOType {
			return r.Name(), nil
		}
	}
	return nil, ErrSelf
}
