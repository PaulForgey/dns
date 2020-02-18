package resolver

import (
	"errors"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/nsdb"
)

type Scope uint

const (
	InCache Scope = 1 << iota
	InAuth

	InAny = InCache | InAuth
)

// the ZoneAuthority interface tells a resolver how to look up authoritative records or delegations
type ZoneAuthority interface {
	// Lookup retrieves authoritative records for the zone, or cached entries if they were entered
	Lookup(key string, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (a []*dns.Record, ns []*dns.Record, err error)
	// MLookup is Lookup with MDNS semantics
	MLookup(key string, where Scope, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) ([]*dns.Record, error)
	// Remove removes records matching name and interface
	Remove(name dns.Name) (IfaceRRSets, error)
	// Hint returns true if this is a hint zone
	Hint() bool
	// Name returns the name of the zone
	Name() dns.Name
	// Enter enters recors into the cache.
	Enter(now time.Time, key string, records []*dns.Record) ([]*dns.Record, error)
}

// the Authority interface defines a container finding closest a matching ZoneAuthority for a given Name
type Authority interface {
	Find(name dns.Name) ZoneAuthority
}

// the UpdateLog interface hooks zone updates.
// XXX this concept belongs in ns
type UpdateLog interface {
	// if Update returns an error, the update does not occur and the error is returned to the caller of the zone's update
	Update(key string, update []*dns.Record) error
}

// the Zone type holds authoritative records for a given DNS zone.
// Records in a zone may further be keyed by interface name.
type Zone struct {
	sync.RWMutex
	name  dns.Name
	hint  bool
	cache *nsdb.Cache
	keys  map[string]*nsdb.Cache
}

// NewZone creates a new zone with a given name
func NewZone(name dns.Name, hint bool) *Zone {
	zone := &Zone{
		name: name,
		hint: hint,
		keys: make(map[string]*nsdb.Cache),
	}
	zone.cache = nsdb.NewCache()
	zone.keys[""] = zone.cache
	return zone
}

func (z *Zone) Hint() bool {
	return z.hint
}

func (z *Zone) Name() dns.Name {
	return z.name
}

// Lookup a name within a zone with MDNS semantics
func (z *Zone) MLookup(
	key string,
	where Scope,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (a []*dns.Record, err error) {
	if (where & InCache) == 0 {
		return
	}

	z.RLock()
	db, ok := z.keys[key]
	if !ok {
		db = z.cache
	}
	z.RUnlock()
	for db != nil {
		var rrset *nsdb.RRSet
		rrset, err = nsdb.Lookup(db, true, name, rrtype, rrclass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return
		}
		if rrset != nil {
			a = dns.Merge(a, rrset.Records)
		}
		if db != z.cache {
			db = z.cache
		} else {
			db = nil
		}
	}

	err = nil
	return
}

// Remove removes a name from a zone, returning its content as an IfaceRRSet
func (z *Zone) Remove(name dns.Name) (IfaceRRSets, error) {
	z.Lock()
	defer z.Unlock()

	rrsets := make(IfaceRRSets)

	for iface, db := range z.keys {
		rrmap, err := db.Lookup(name)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, err
		}
		for _, rrset := range rrmap {
			rrsets[iface] = append(rrsets[iface], rrset.Records...)
		}
		if err := db.Enter(name, nil); err != nil {
			return nil, err
		}
	}

	return rrsets, nil
}

// Lookup a name within a zone, or a delegation above it.
func (z *Zone) Lookup(
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	z.RLock()
	db, ok := z.keys[key]
	z.RUnlock()
	if !ok {
		db = z.cache
	}

	var a, ns []*dns.Record
	var err error

	for db != nil {
		a, ns, err = z.LookupDb(db, name, rrtype, rrclass)
		if errors.Is(err, dns.NXDomain) {
			if db != z.cache {
				db = z.cache
			} else {
				db = nil
			}
		} else {
			break
		}
	}

	return a, ns, err
}

func (z *Zone) LookupDb(
	db nsdb.Db,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	rrset, err := nsdb.Lookup(db, false, name, rrtype, rrclass)
	if rrset != nil {
		return rrset.Records, nil, nil
	}
	if err != nil && !errors.Is(err, dns.NXDomain) {
		return nil, nil, err
	}

	// try for delegation
	if name.HasSuffix(z.name) {
		if rrtype == dns.NSType {
			if len(name) > len(z.name) {
				name = name.Suffix()
			} else {
				return nil, nil, err
			}
		}
		// do not dig in ourselves unless we are a hint zone
		if len(name) == len(z.name) && !z.hint {
			return nil, nil, err
		}

		rrset, nsset, err2 := z.LookupDb(db, name, dns.NSType, rrclass)
		if rrset != nil || (err2 != nil && !errors.Is(err2, dns.NXDomain)) {
			// delegation response or error getting it
			return nil, rrset, err2
		}
		if nsset != nil {
			return nil, nsset, nil
		}
	}

	// return original empty set or NXDomain
	return nil, nil, err
}

// Enter loads items into the cache. If now is zero value, these are permanent and non-overwritable entries.
// XXX do not cache pseduo records
func (z *Zone) Enter(now time.Time, key string, records []*dns.Record) ([]*dns.Record, error) {
	var db *nsdb.Cache
	z.Lock()
	db, ok := z.keys[key]
	if !ok {
		db = nsdb.NewCache()
		z.keys[key] = db
	}
	z.Unlock()
	_, err := nsdb.Load(db, now, records)
	return nil, err
}
