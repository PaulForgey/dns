package nsdb

import (
	"errors"
	"math/rand"
	"time"

	"tessier-ashpool.net/dns"
)

var ErrInvalidRRSet = errors.New("invalid rrset")
var ErrAlreadyUpdating = errors.New("already in update context")
var ErrNotUpdating = errors.New("no update context")

// the RRSet type is a value for a given name, type and class
type RRSet struct {
	Entered   time.Time // Used by Expire. Zero value means TTL is never adjusted.
	Exclusive bool      // MDNS: name+type+class is not shared
	Records   []*dns.Record
}

// the RRMap type is a set of values for a given name (fundamental DB storage)
type RRMap map[RRKey]*RRSet

// the RRKey is the key value for an RRMAP
type RRKey struct {
	RRType  dns.RRType
	RRClass dns.RRClass
}

type DbFlags int

const (
	// Changes to data are immediately reflected, with no later call to Save() necessary
	DbLiveUpdateFlag DbFlags = 1 << iota

	// Retrievals are high latency and should be cached locally
	DbShouldCacheFlag
)

// the Db interface defines an instance of a database back end.
// After storing or retrieving an *RRset instance, use RRSet.Copy to make a mutable shallow copy if it will be modified.
type Db interface {
	// Flags returns information about the database instance.
	Flags() DbFlags

	// Lookup returns an RRSet. If not records exist for the name, returns NXDomain.
	// Empty RRMaps are never returned, so existence check is simply a check against nil.
	// CAUTION: the returned RRMap should be treated as immutable
	Lookup(name dns.Name) (RRMap, error)

	// Enter replaces an RRMap for a given name.
	// CAUTION: the database instance takes over ownership of this RRMap
	Enter(name dns.Name, value RRMap) error

	// Snapshot snapshots the database at a given serial number. If not supported, Snapshot does nothing and
	// returns no error. Snapshotting the same serial has no subsequent effect.
	Snapshot(serial uint32) error

	// Enumerate returns all records in the database. If starting serial is not found or backend does not
	// support snapshotting, a full set is returned, indicated by the serial parameter in f set to 0.
	// If snapshotted, result will be a delta to current, with serial indicating records to be removed.
	Enumerate(serial uint32, f func(serial uint32, records []*dns.Record) error) error

	// Begins an update transaction. There can be only one
	BeginUpdate() error

	// Commits the update transaction
	EndUpdate(abort bool) error

	// Save commits cached or in-memory changes to stable storage.
	Save() error

	// Clear resets the database.
	// XXX This method presumes populating from a zone file, which will ultimately be handled by the backend
	Clear() error
}

// Lookup is a convenience function to wrap looking up an RRMap and then searching it
func Lookup(db Db, exact bool, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error) {
	value, err := db.Lookup(name)
	if err != nil {
		return nil, err
	}
	return value.Lookup(exact, rrtype, rrclass), nil
}

// Enter is a convience function to wrap looking up an RRMap, copying it, updating, then storing it
func Enter(db Db, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, rr *RRSet) error {
	value, err := db.Lookup(name)
	if err != nil && !errors.Is(err, dns.NXDomain) {
		return err
	}
	if value == nil {
		value = make(RRMap)
	} else {
		value = value.Copy()
	}
	value.Enter(rrtype, rrclass, rr)
	return db.Enter(name, value)
}

// Load is a convenience function to load up a batch of records to throw in to the database.
// The slice of records will end up sorted by name.
func Load(db Db, entered time.Time, records []*dns.Record) (bool, error) {
	added := false
	err := dns.RecordSets(
		records,
		func(name dns.Name, records []*dns.Record) error {
			value, err := db.Lookup(name)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return err
			}
			if value == nil {
				value = make(RRMap)
			} else {
				value = value.Copy()
			}
			if value.Load(entered, records) {
				added = true
			}
			return db.Enter(name, value)
		},
	)
	return added, err
}

// Patch is a convenience function to remove records from remove and add from add.
// This uses a combination of IXFR/update rules. Exact matches are removed, AnyType or AnyClass removes rrsets.
// Returns true if the patch resulted in records being deletd.
func Patch(db Db, remove []*dns.Record, add []*dns.Record) (bool, error) {
	updated := false
	err := dns.RecordSets(
		remove,
		func(name dns.Name, records []*dns.Record) error {
			value, err := db.Lookup(name)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return err
			}
			if value == nil {
				return nil // nothing to remove
			} else {
				value = value.Copy()
			}

			if value.Subtract(records) {
				updated = true
				return db.Enter(name, value)
			}
			return nil
		},
	)
	if err != nil {
		return false, err
	}
	added, err := Load(db, time.Time{}, add)
	if err != nil {
		return updated, err
	}
	return added || updated, nil
}

// Match returns true if rrtype and rrclass ask for the associated set.
// If exact is true, do not match CNAMEType unless it is being asked for.
func (r RRKey) Match(exact bool, rrtype dns.RRType, rrclass dns.RRClass) bool {
	if rrtype.Asks(r.RRType) && rrclass.Asks(r.RRClass) {
		return !(exact && (rrtype != dns.AnyType && rrtype != r.RRType))
	}
	return false
}

// Get returns an RRSet by type and class
func (r RRMap) Get(rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, bool) {
	rrset, ok := r[RRKey{rrtype, rrclass}]
	return rrset, ok
}

// Copy creates a copy of r. The data of the actual records are not copied.
func (r RRMap) Copy() RRMap {
	n := make(RRMap)
	for k, v := range r {
		if v != nil {
			n[k] = v.Copy()
		}
	}
	return n
}

// Set replaces or deletes an rrset by type and class.
func (r RRMap) Set(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) {
	key := RRKey{rrtype, rrclass}
	if rrset == nil {
		delete(r, key)
	} else {
		r[key] = rrset
	}
}

// Expire updates an RRMap backdating TTLs of surviving records and deleting others
func (r RRMap) Expire(now time.Time) {
	for k, v := range r {
		if v.Expire(now) {
			delete(r, k)
		}
	}
}

// Lookup returns matching RRSet entries.
// If exact is true, CNAMEs are not returned unless asked for.
func (r RRMap) Lookup(exact bool, rrtype dns.RRType, rrclass dns.RRClass) *RRSet {
	var rrset *RRSet

	if !exact && rrclass != dns.AnyClass {
		rrset, _ = r.Get(dns.CNAMEType, rrclass)
		if rrset != nil {
			return rrset
		}
	}

	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		rrset = &RRSet{}
		for t, rs := range r {
			if t.Match(exact, rrtype, rrclass) {
				if rrset.Records == nil {
					rrset.Exclusive = rs.Exclusive
				} else {
					rrset.Exclusive = rrset.Exclusive && rs.Exclusive
				}
				rrset.Records = append(rrset.Records, rs.Records...)
			}
		}
	} else {
		rrset, _ = r.Get(rrtype, rrclass)
		if rrset != nil && len(rrset.Records) > 1 {
			rrset = rrset.Copy()
		}
	}

	return rrset
}

// Enter updates an RRMap with a new entry for the rrtype and rrclass.
// If rrtype is AnyType or rrclass is AnyClass, delete the matching entries.
func (r RRMap) Enter(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error {
	if rrset != nil && len(rrset.Records) == 0 {
		rrset = nil
	}
	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		if rrset != nil {
			return ErrInvalidRRSet
		}
		for t := range r {
			if t.Match(true, rrtype, rrclass) {
				delete(r, t)
			}
		}
	} else {
		r.Set(rrtype, rrclass, rrset)
	}
	return nil
}

// Subtract removes records from r
// return true if the map was actually mutated
func (r RRMap) Subtract(records []*dns.Record) bool {
	mutated := false
	for _, d := range records {
		if d.D != nil {
			key := RRKey{d.H.Type(), d.H.Class()}
			rrset, ok := r[key]
			if !ok {
				continue
			}
			olen := len(rrset.Records)
			nr := dns.Subtract(rrset.Records, records)
			nlen := len(nr)
			if nlen != olen {
				mutated = true
			}
			if nlen == 0 {
				delete(r, key)
			} else {
				r[key] = &RRSet{
					Entered:   rrset.Entered,
					Exclusive: rrset.Exclusive,
					Records:   nr,
				}
			}
		} else {
			for key, _ := range r {
				if key.Match(true, d.H.Type(), d.H.Class()) {
					mutated = true
					delete(r, key)
				}
			}
		}
	}
	return mutated
}

// Load enters a series of records into the map
// entries with TTL 0 will be modified to TTL 1
func (r RRMap) Load(entered time.Time, records []*dns.Record) bool {
	added := false
	n := make(RRMap)
	for _, r := range records {
		key := RRKey{r.H.Type(), r.H.Class()}
		rrset, ok := n[key]
		if !ok {
			rrset = &RRSet{Entered: entered}
			n[key] = rrset
		}
		if r.H.TTL() < time.Second {
			r.H.SetTTL(time.Second)
		}
		if dns.CacheFlush(r.H) != rrset.Exclusive {
			// discard non exclusive records if exclusive ones are present
			if !rrset.Exclusive {
				rrset.Exclusive = true
				rrset.Records = nil
			} else {
				continue
			}
		}
		rrset.Records = append(rrset.Records, r)
	}
	for k, v := range n {
		rrset, ok := r[k]
		if !ok {
			r[k] = v
			added = true
		} else {
			if rrset.Entered.IsZero() && !entered.IsZero() {
				continue
			}
			if v.Exclusive {
				r[k] = v
			} else {
				rrset.Merge(v.Records)
			}
			added = true
		}
	}
	return added
}

// Expire updates an RRSet backdating the TTLs and removing expired records
// If the RRSet has an zero Entered value, Expire does nothing
// If the entire RRSet goes away, Expire returns true to indicate it may be purged entirely
func (rs *RRSet) Expire(now time.Time) bool {
	if rs.Entered.IsZero() {
		return false
	}
	if now.Before(rs.Entered) {
		now = rs.Entered
	}
	records := make([]*dns.Record, 0)
	since := now.Sub(rs.Entered)
	for _, r := range rs.Records {
		expires := rs.Entered.Add(r.H.TTL())
		if !now.Before(expires) { // now >= expires
			continue
		}
		// add the surviving record back in after adjusting
		r.H.SetTTL(r.H.TTL() - since.Round(time.Second))

		records = append(records, r)
	}
	rs.Entered = now
	rs.Records = records
	return len(records) == 0
}

// Merge combines two sets of records excluding duplicates
func (rs *RRSet) Merge(records []*dns.Record) {
	// favor the new records in duplicates to update TTL
	rs.Records = dns.Merge(rs.Records, records)
}

// Exclude returns records not in rs
func (rs *RRSet) Exclude(records []*dns.Record) []*dns.Record {
	var nr []*dns.Record

	for _, rr := range records {
		found := false
		if rr.D == nil {
			continue
		}
		for _, or := range rs.Records {
			if or.D.Equal(rr.D) {
				found = true
				break
			}
		}
		if !found {
			nr = append(nr, rr)
		}
	}

	return nr
}

// Subtract removes records from rs.
// returns true if the operation completely clears the rrset
func (rs *RRSet) Subtract(records []*dns.Record) bool {
	rs.Records = dns.Subtract(rs.Records, records)
	return len(rs.Records) == 0
}

// Copy creates a new RRSet shallow copy randomly rotated
func (rs *RRSet) Copy() *RRSet {
	nr := &RRSet{Entered: rs.Entered, Exclusive: rs.Exclusive}
	if len(rs.Records) > 0 {
		l := len(rs.Records)
		nr.Records = make([]*dns.Record, l)
		i := rand.Int() % l
		copy(nr.Records, rs.Records[i:])
		if i > 0 {
			copy(nr.Records[l-i:], rs.Records[:i])
		}
	}
	return nr
}
