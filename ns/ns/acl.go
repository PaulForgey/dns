package main

import (
	"net"
	"strings"

	"tessier-ashpool.net/dns/ns"
)

type acls struct {
	c    *Conf
	list *[]string
}

func (c *Conf) Access(list *[]string) ns.Access {
	return &acls{c: c, list: list}
}

func (a *acls) Check(from net.Addr, iface string, resource string) bool {
	a.c.RLock()
	defer a.c.RUnlock()

	for _, name := range *(a.list) {
		acl, ok := a.c.ACLs[name]
		if !ok {
			logger.Printf("unknown acl %s", name)
			continue
		}
		if acl.Check(from, iface, resource) {
			return true
		}
	}

	return false
}

func (a ACL) Check(from net.Addr, iface string, resource string) bool {
	if len(a) == 0 {
		return false
	}

	for _, ace := range a {
		if ace.InterfaceName != "" && ace.InterfaceName != iface {
			return false
		}
		if ace.Resource != "" && !strings.HasPrefix(resource, ace.Resource) {
			return false
		}
		if ace.CIDR != nil {
			if from == nil {
				return false
			}
			var ip net.IP

			switch t := from.(type) {
			case *net.IPAddr:
				ip = t.IP
			case *net.TCPAddr:
				ip = t.IP
			case *net.UDPAddr:
				ip = t.IP
			}

			if ip == nil {
				return false // source addr not IP
			}
			if !ace.CIDR.IPNet.Contains(ip) {
				return false
			}
		}
	}

	return true
}
