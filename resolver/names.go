package resolver

import (
	"fmt"
	"net"
	"strings"

	"tessier-ashpool.net/dns"
)

// ArpaName takes the given ip address and returns a name for it in the .arpa domain
func ArpaName(ip net.IP) dns.Name {
	s := &strings.Builder{}
	ip4 := ip.To4()
	if ip4 != nil {
		fmt.Fprintf(s, "%d.%d.%d.%d.in-addr.arpa", ip4[3], ip4[2], ip4[1], ip4[0])
	} else if len(ip) == 16 {
		for i := 15; i >= 0; i-- {
			fmt.Fprintf(s, "%x.%x.", ip[i]&0xf, ip[i]>>4)
		}
		s.WriteString("ip6.arpa")
	} else {
		return nil
	}
	name, err := dns.NameWithString(s.String())
	if err != nil {
		panic(err) // no legitimate reason for this to be unparseable
	}

	return name
}
