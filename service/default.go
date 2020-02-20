// +build !windows

package service

import (
	"bufio"
	"net"
	"os"
	"strings"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

const mdnsSocket = "/var/run/mDNS/mDNS-socket"

func defaultServices() *Services {
	services := &Services{
		domains: make(map[string][]Service),
	}
	var nsaddrs []net.Addr

	local, err := dns.NameWithString("local")
	if err != nil {
		panic(err)
	}

	f, err := os.Open("/etc/resolv.conf")
	if err == nil {
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.Fields(s.Text())
			if len(line) == 0 {
				continue
			}
			switch line[0] {
			case "search", "domain":
				for _, search := range line[1:] {
					name, err := dns.NameWithString(search)
					if err == nil {
						services.Search = append(services.Search, name)
					}
				}

			case "nameserver":
				for _, ns := range line[1:] {
					host, port, err := net.SplitHostPort(ns)
					if err != nil {
						port = "53"
						host = ns
					}
					udp, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
					if err == nil {
						nsaddrs = append(nsaddrs, udp)
					}
				}
			}
		}
	}

	r, err := resolver.NewResolverClient(resolver.EmptyCache, "udp", "", nsaddrs, true)
	if err == nil {
		services.domains[""] = []Service{&dnsService{r}}
	}
	mr, err := resolver.NewMResolverClient("unix", mdnsSocket)
	if err == nil {
		service := &mdnsService{mr}
		services.Search = append([]dns.Name{local}, services.Search...)
		services.Update = []dns.Name{local}
		services.domains[local.Key()] = []Service{service}

		for _, r := range []string{
			"254.169.in-addr.arpa",
			"8.e.f.ip6.arpa",
			"9.e.f.ip6.arpa",
			"a.e.f.ip6.arpa",
			"b.e.f.ip6.arpa",
		} {
			name, err := dns.NameWithString(r)
			if err != nil {
				panic(err)
			}
			services.domains[name.Key()] = []Service{service}
		}
	}

	return services
}
