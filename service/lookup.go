package service

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

// LookupAddr performs a reverse lookup for the given address.
func (s *Services) LookupAddr(ctx context.Context, addr net.IP) ([]string, error) {
	name := resolver.ArpaName(addr)
	answers, err := s.Lookup(ctx, name.String(), dns.PTRType, dns.INClass)
	if err != nil {
		return nil, err
	}

	records := answers.AllRecords()
	hosts := make([]string, 0, len(records))
	for _, r := range records {
		if ptr, _ := r.D.(*dns.PTRRecord); ptr != nil {
			hosts = append(hosts, ptr.Name.String())
		}
	}

	return hosts, nil
}

// LookupIPAddr resolves IP addresses for the given host
func (s *Services) LookupIPAddr(ctx context.Context, host string) ([]*net.IPAddr, error) {
	answers := make(resolver.IfaceRRSets)

	for _, t := range []dns.RRType{dns.AType, dns.AAAAType} {
		a, err := s.Lookup(ctx, host, t, dns.INClass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, err
		}
		answers.Merge(a)
	}

	var addrs []*net.IPAddr
	for iface, records := range answers {
		for _, r := range records {
			if iprecord, ok := r.D.(dns.IPRecordType); ok {
				var addr net.IPAddr

				addr.IP = iprecord.IP()
				if addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() {
					addr.Zone = iface
				}

				addrs = append(addrs, &addr)
			}
		}
	}

	return addrs, nil
}

// LookupHost resolves addresses of the given network and host
func (s *Services) LookupHost(ctx context.Context, network, host string) ([]net.Addr, error) {
	var types []dns.RRType
	answers := make(resolver.IfaceRRSets)

	switch network {
	case "udp", "tcp", "ip":
		types = []dns.RRType{dns.AAAAType, dns.AType}
	case "udp4", "tcp4", "ip4":
		types = []dns.RRType{dns.AType}
	case "udp6", "tcp6", "ip6":
		types = []dns.RRType{dns.AAAAType}
	default:
		return nil, fmt.Errorf("%w: %s", ErrBadProtocol, network)
	}

	for _, t := range types {
		a, err := s.Lookup(ctx, host, t, dns.INClass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, err
		}
		answers.Merge(a)
	}

	var addrs []net.Addr
	for iface, records := range answers {
		for _, r := range records {
			if iprecord, ok := r.D.(dns.IPRecordType); ok {
				var addr net.IPAddr

				addr.IP = iprecord.IP()
				if addr.IP.IsLinkLocalUnicast() || addr.IP.IsLinkLocalMulticast() {
					addr.Zone = iface
				}

				addrs = append(addrs, &addr)
			}
		}
	}

	return addrs, nil
}

// LookupSRV resolves SRV records
func (s *Services) LookupSRV(ctx context.Context, service, proto, name string) ([]*dns.SRVRecord, error) {
	var sname string
	if service != "" {
		sname = "_" + service + "."
	}
	if proto != "" {
		sname += "_" + proto + "."
	}
	sname += name

	answers, err := s.Lookup(ctx, sname, dns.SRVType, dns.INClass)
	if err != nil {
		return nil, err
	}

	records := answers.AllRecords()
	srvs := make([]*dns.SRVRecord, 0, len(records))
	for _, r := range records {
		if srv, ok := r.D.(*dns.SRVRecord); ok {
			srvs = append(srvs, srv)
		}
	}

	// randomize within priorities
	rand.Shuffle(len(srvs), func(i, j int) { srvs[i], srvs[j] = srvs[j], srvs[i] })
	sort.Slice(srvs, func(i, j int) bool { return srvs[i].Priority < srvs[j].Priority })

	return srvs, nil
}

// LookupMX resolves MX records
func (s *Services) LookupMX(ctx context.Context, name string) ([]*dns.MXRecord, error) {
	answers, err := s.Lookup(ctx, name, dns.MXType, dns.INClass)
	if err != nil {
		return nil, err
	}

	records := answers.AllRecords()
	mxs := make([]*dns.MXRecord, 0, len(records))
	for _, r := range records {
		if mx, ok := r.D.(*dns.MXRecord); ok {
			mxs = append(mxs, mx)
		}
	}

	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Preference < mxs[j].Preference })
	return mxs, nil
}

// Locate returns a priority ordered list of addresses of the approriate protocol for a given service name, type, and protocol
func (s *Services) Locate(
	ctx context.Context,
	name, serviceType, protocol string,
) ([]net.Addr, map[string]string, error) {
	var protoName string

	switch protocol {
	case "udp", "udp4", "udp6":
		protoName = "udp"
	case "tcp", "tcp4", "tcp6":
		protoName = "tcp"
	default:
		return nil, nil, fmt.Errorf("%w: %s", ErrBadProtocol, protocol)
	}

	var sname string
	if name != "" {
		sname = name + "."
	}
	sname += "_" + serviceType + "._" + protoName
	answers, err := s.Lookup(ctx, sname, dns.AnyType, dns.INClass)
	if err != nil {
		return nil, nil, err
	}

	var txtRecords []*dns.TXTRecord
	var srvRecords []*dns.SRVRecord

	for _, r := range answers.AllRecords() {
		switch t := r.D.(type) {
		case *dns.TXTRecord:
			txtRecords = append(txtRecords, t)

		case *dns.SRVRecord:
			srvRecords = append(srvRecords, t)
		}
	}

	txt := make(map[string]string)
	for _, r := range txtRecords {
		for _, t := range r.Text {
			t = strings.ToLower(t)
			values := strings.SplitN(t, "=", 2)
			if len(values) > 1 {
				txt[values[0]] = values[1]
			}
		}
	}

	// randomize within priorities
	rand.Shuffle(len(srvRecords), func(i, j int) { srvRecords[i], srvRecords[j] = srvRecords[j], srvRecords[i] })
	sort.Slice(srvRecords, func(i, j int) bool { return srvRecords[i].Priority < srvRecords[j].Priority })

	hostAddrs := make(map[string][]net.Addr)
	var addrs []net.Addr

	for _, srv := range srvRecords {
		ips, _ := hostAddrs[srv.Name.Key()]
		if ips == nil {
			ips, err = s.LookupHost(ctx, protocol, srv.Name.String())
			if err != nil {
				return nil, nil, err
			}
			hostAddrs[srv.Name.Key()] = ips
			addrs = append(addrs, ips...)
		}
	}

	return addrs, txt, nil
}
