package resolver

import (
	"strings"

	"tessier-ashpool.net/dns"
)

const rootZone = `
.			518400	IN	NS	m.root-servers.net.
.			518400	IN	NS	b.root-servers.net.
.			518400	IN	NS	c.root-servers.net.
.			518400	IN	NS	d.root-servers.net.
.			518400	IN	NS	e.root-servers.net.
.			518400	IN	NS	f.root-servers.net.
.			518400	IN	NS	g.root-servers.net.
.			518400	IN	NS	h.root-servers.net.
.			518400	IN	NS	a.root-servers.net.
.			518400	IN	NS	i.root-servers.net.
.			518400	IN	NS	j.root-servers.net.
.			518400	IN	NS	k.root-servers.net.
.			518400	IN	NS	l.root-servers.net.
m.root-servers.net.	518400	IN	A	202.12.27.33
m.root-servers.net.	518400	IN	AAAA	2001:dc3::35
b.root-servers.net.	518400	IN	A	199.9.14.201
b.root-servers.net.	518400	IN	AAAA	2001:500:200::b
c.root-servers.net.	518400	IN	A	192.33.4.12
c.root-servers.net.	518400	IN	AAAA	2001:500:2::c
d.root-servers.net.	518400	IN	A	199.7.91.13
d.root-servers.net.	518400	IN	AAAA	2001:500:2d::d
e.root-servers.net.	518400	IN	A	192.203.230.10
e.root-servers.net.	518400	IN	AAAA	2001:500:a8::e
f.root-servers.net.	518400	IN	A	192.5.5.241
f.root-servers.net.	518400	IN	AAAA	2001:500:2f::f
g.root-servers.net.	518400	IN	A	192.112.36.4
g.root-servers.net.	518400	IN	AAAA	2001:500:12::d0d
h.root-servers.net.	518400	IN	A	198.97.190.53
h.root-servers.net.	518400	IN	AAAA	2001:500:1::53
a.root-servers.net.	518400	IN	A	198.41.0.4
a.root-servers.net.	518400	IN	AAAA	2001:503:ba3e::2:30
i.root-servers.net.	518400	IN	A	192.36.148.17
i.root-servers.net.	518400	IN	AAAA	2001:7fe::53
j.root-servers.net.	518400	IN	A	192.58.128.30
j.root-servers.net.	518400	IN	AAAA	2001:503:c27::2:30
k.root-servers.net.	518400	IN	A	193.0.14.129
k.root-servers.net.	518400	IN	AAAA	2001:7fd::1
l.root-servers.net.	518400	IN	A	199.7.83.42
l.root-servers.net.	518400	IN	AAAA	2001:500:9f::42
`

// Root is the set of glue records for the zone '.'
func NewRootZone() *Zone {
	zone := NewZone(nil, true)

	c := dns.NewTextReader(strings.NewReader(rootZone), nil)
	err := zone.Decode("", false, c)
	if err != nil {
		panic(err)
	}

	return zone
}

type rootCache struct {
	root *Zone
}

func (r rootCache) Find(_ dns.Name) ZoneAuthority {
	return r.root
}

// RootCache is a global Authority containing only . suitable for caching
var RootCache rootCache = rootCache{NewRootZone()}

// EmptyCache is like RootCache but without any hints
var EmptyCache rootCache = rootCache{NewZone(nil, true)}
