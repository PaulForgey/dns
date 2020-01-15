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
}

// the Zone type is a specialization of the resolver Zone with additional information needed by the server
type Zone struct {
	*resolver.Zone
	Primary       string
	AllowQuery    Access
	AllowUpdate   Access
	AllowTransfer Access
	AllowNotify   Access

	online bool
	r      chan bool // reload
	u      chan bool // update

	// update hazard
	updateWait   *sync.WaitGroup
	updateLock   *sync.Mutex
	updateCond   *sync.Cond
	blockUpdates bool
}

// NewZone creates a new, empty zone for use by the server
func NewZone(z *resolver.Zone) *Zone {
	lock := &sync.Mutex{}
	return &Zone{
		Zone:       z,
		r:          make(chan bool, 1),
		u:          make(chan bool, 1),
		updateWait: &sync.WaitGroup{},
		updateLock: lock,
		updateCond: sync.NewCond(lock),
	}
}

// Reload signals the zone to reload by making the channel in ReloadC() readable
func (z *Zone) Reload() {
	select {
	case z.r <- true:
	default: // don't block
	}
}

// Notify signals the zone to send notifications of an update by making the channel in UpdateC() reable
func (z *Zone) Notify() {
	select {
	case z.u <- true:
	default: // don't block
	}
}

// ReloadC returns a channel which is readable when the zone requests to be reloaded
func (z *Zone) ReloadC() <-chan bool {
	return z.r
}

// NotifyC returns a channel which is readable when the zone requests to send notifications
func (z *Zone) NotifyC() <-chan bool {
	return z.u
}

// HoldUpdates blocks updates from occuring until ReloadUpdates is called
func (z *Zone) HoldUpdates() {
	z.updateLock.Lock()
	if z.blockUpdates {
		panic("HoldUpdates on held updates")
	}
	z.blockUpdates = true
	z.updateLock.Unlock()
	z.updateWait.Wait()
}

func (z *Zone) ReleaseUpdates() {
	z.updateLock.Lock()
	if !z.blockUpdates {
		panic("ReleaseUpdates on released updated")
	}
	z.blockUpdates = false
	z.updateCond.Broadcast()
	z.updateLock.Unlock()
}

func (z *Zone) EnterUpdateFence() {
	z.updateLock.Lock()
	for z.blockUpdates {
		z.updateCond.Wait()
	}
	z.updateWait.Add(1)
	z.updateLock.Unlock()
}

func (z *Zone) LeaveUpdateFence() {
	z.updateWait.Done()
}

// NewZones creates an empty Zones
func NewZones() *Zones {
	return &Zones{
		zones: make(map[string]*Zone),
	}
}

// Insert adds or overwrites a zone
func (zs *Zones) Insert(z *Zone, online bool) {
	zs.Lock()
	z.online = online
	zs.zones[z.Name().Key()] = z
	zs.Unlock()
}

// Remove removes a zone
func (zs *Zones) Remove(z *Zone) {
	zs.Lock()
	z.online = false
	delete(zs.zones, z.Name().Key())
	zs.Unlock()
}

// Offline marks a zone offline
func (zs *Zones) Offline(z *Zone) {
	zs.Lock()
	z.online = false
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

	if z != nil && !z.online {
		z = nil
	}

	zs.RUnlock()
	if z == nil {
		return nil
	}
	return z
}

// Zone returns the zone by exact match, online or not
func (zs *Zones) Zone(n dns.Name) *Zone {
	zs.RLock()
	z, _ := zs.zones[n.Key()]
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
