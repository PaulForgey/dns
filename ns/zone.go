package ns

import (
	"sync"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

// the Zones type holds all the zones we know of
type Zones struct {
	R *resolver.Resolver
	sync.RWMutex
	zones map[string]*Zone

	// XXX global unicast server options
}

// the Zone type is a specialization of the resolver Zone with additional information needed by the server
type Zone struct {
	*resolver.Zone
	C chan bool // reload

	// XXX access control
}

func NewZone(z *resolver.Zone) *Zone {
	return &Zone{
		Zone: z,
		C:    make(chan bool, 1),
	}
}

func (z *Zone) Reload() {
	select {
	case z.C <- true:
		// don't block
	}
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
	zs.zones[z.Name().Key()] = z
	zs.Unlock()
}

// Remove removes a zone (takes it offline)
func (zs *Zones) Remove(z *Zone) {
	zs.Lock()
	delete(zs.zones, z.Name().Key())
	zs.Unlock()
}

// Finds a zone by name having the closest common suffix.
// Find can return nil if the root zone is not present.
func (zs *Zones) Find(n dns.Name) resolver.ZoneAuthority {
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

// Additional fills in the additional section if it can from either cache or authority
func (zs *Zones) Additional(msg *dns.Message, key string, rrclass dns.RRClass) {
	records := make([]*dns.Record, len(msg.Authority), len(msg.Authority)+len(msg.Answers))
	copy(records, msg.Authority)
	records = append(records, msg.Answers...)

	for i := 0; i < len(records); i++ {
		rec := records[i]

		var name dns.Name
		var rrtype dns.RRType

		switch rec.Type() {
		case dns.AType:
			rrtype = dns.AAAAType
			name = rec.RecordHeader.Name

		case dns.AAAAType:
			rrtype = dns.AType
			name = rec.RecordHeader.Name

		default:
			if n, ok := rec.RecordData.(dns.NameRecordType); ok {
				name = n.RName()
				rrtype = dns.AnyType
			}
		}

		if name == nil {
			continue
		}

		// make sure we haven't already put it in
		found := false
		for _, a := range msg.Additional {
			if a.RecordHeader.Name.Equal(name) && rrtype.Asks(a.Type()) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		for _, a := range msg.Answers {
			if a.RecordHeader.Name.Equal(name) && rrtype.Asks(a.Type()) {
				found = true
				break
			}
		}
		if found {
			continue
		}

		zone := zs.Find(name)
		if zone == nil {
			continue
		}

		// find it from cache
		answers, _, _ := zone.Lookup(key, name, rrtype, rrclass)
		if len(answers) == 0 {
			return
		}

		for _, a := range answers {
			switch a.Type() {
			case dns.AType, dns.AAAAType, dns.TXTType, dns.PTRType, dns.SRVType:
				msg.Additional = append(msg.Additional, a)
				records = append(records, a)
			}
		}
	}
}
