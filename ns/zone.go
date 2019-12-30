package ns

import (
	"sync"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

// the Zones type holds all the zones we know of
type Zones struct {
	sync.RWMutex
	zones map[string]*Zone
	// XXX global unicast server options
}

// the Zone type is a specialization of the resolver Zone with additional information needed by the server
type Zone struct {
	*resolver.Zone
	R *resolver.Resolver // if we support recursion on this zone
	// XXX primary, secondary, access control, etc
}

// NewZones creates an empty Zones
func NewZones() *Zones {
	return &Zones{
		zones: make(map[string]*Zone),
	}
}

// Insert adds or overwrites a zone
func (zs *Zones) Insert(z *Zone) {
	zs.Lock()
	zs.zones[z.Name.Key()] = z
	zs.Unlock()
}

// Finds a zone by name having the closest common suffix.
// Find can return nil if the root zone is not present.
func (zs *Zones) Find(n dns.Name) *Zone {
	var z *Zone
	var ok bool

	zs.RLock()

	for {
		z, ok = zs.zones[n.Key()]
		if ok || len(n) == 0 {
			break
		}
		n = n.Suffix()
	}

	zs.RUnlock()
	return z
}

// Additional fills in the additional section given a NameRecordType if it can from either cache or authority
func (zs *Zones) Additional(msg *dns.Message, key string, rrclass dns.RRClass, nrec dns.NameRecordType) {
	name := nrec.Name()
	// make sure we haven't already put it in
	for _, a := range msg.Additional {
		if a.RecordHeader.Name.Equal(name) {
			return
		}
	}
	zone := zs.Find(name)
	if zone == nil {
		return
	}
	answers, _, _ := zone.Lookup(key, name, dns.AnyType, rrclass)
	if len(answers) == 0 {
		return
	}

	for _, a := range answers {
		switch a.Type() {
		case dns.AType, dns.AAAAType, dns.TXTType:
			msg.Additional = append(msg.Additional, a)
		}
	}
}
