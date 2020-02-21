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

// Locate returns a priority ordered list of addresses of the approriate protocol for a given service name, type, and protocol
func (s *Services) Locate(ctx context.Context, name, serviceType, protocol string) ([]net.Addr, map[string]string, error) {
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
		sname = fmt.Sprintf("%s._%s._%s", name, serviceType, protoName)
	} else {
		sname = fmt.Sprintf("_%s._%s", serviceType, protoName)
	}
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

	hostAddrs := make(map[string][]*net.IPAddr)
	var addrs []net.Addr

	for _, srv := range srvRecords {
		ips, _ := hostAddrs[srv.Name.Key()]
		if ips == nil {
			ips, err = s.LookupIPAddr(ctx, srv.Name.String())
			if err != nil {
				return nil, nil, err
			}
			hostAddrs[srv.Name.Key()] = ips
		}

		var addr net.Addr

		for _, ip := range ips {
			ip4 := ip.IP.To4()

			switch protocol {
			case "udp", "udp4", "udp6":
				if (protocol == "udp4" && ip4 == nil) || (protocol == "udp6" && ip4 != nil) {
					continue
				}
				addr = &net.UDPAddr{
					IP:   ip.IP,
					Zone: ip.Zone,
					Port: int(srv.Port),
				}

			case "tcp", "tcp4", "tcp6":
				if (protocol == "tcp4" && ip4 == nil) || (protocol == "tcp6" && ip4 != nil) {
					continue
				}
				addr = &net.TCPAddr{
					IP:   ip.IP,
					Zone: ip.Zone,
					Port: int(srv.Port),
				}
			}

			if addr != nil {
				addrs = append(addrs, addr)
			}
		}
	}

	return addrs, txt, nil
}
