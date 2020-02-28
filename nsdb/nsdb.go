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
var ErrNegativeAnswer = &negativeAnswer{} // NXDomain with cached negative response

type negativeAnswer struct{}

func (e *negativeAnswer) Error() string {
	return "negative cache answer"
}
func (e *negativeAnswer) Unwrap() error {
	return dns.NXDomain
}

// the RRSet type is a value for a given name, type and class
type RRSet struct {
	Entered time.Time // Used by Expire. Zero value means TTL is never adjusted.
	Records []*dns.Record
}

// the RRMap type is a set of values for a given name (fundamental DB storage)
type RRMap struct {
	Map       map[RRKey]*RRSet
	Exclusive bool      // MDNS: name is not shared
	Negative  time.Time // cache: expiration time of negative cache entry
	Sticky    bool      // cache: never expire
}

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
	Lookup(name dns.Name) (*RRMap, error)

	// Enter replaces an RRMap for a given name.
	// CAUTION: the database instance takes over ownership of this RRMap
	Enter(name dns.Name, value *RRMap) error

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
	Clear() error
}

func NewRRMap() *RRMap {
	return &RRMap{
		Map: make(map[RRKey]*RRSet),
	}
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
		value = NewRRMap()
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
				value = NewRRMap()
			} else {
				value = value.Copy()
			}
			if value.Load(entered, records) {
				added = true
			}
			if entered.IsZero() {
				value.Sticky = true
			}
			return db.Enter(name, value)
		},
	)
	return added, err
}

// Patch is a convenience function to remove records from remove and add from add.
// This uses a combination of IXFR/update rules. Exact matches are removed, AnyType or AnyClass removes rrsets.
// Returns true if the patch resulted in records being deletd.
func Patch(db Db, entered time.Time, remove []*dns.Record, add []*dns.Record) (bool, error) {
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
	added, err := Load(db, entered, add)
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
func (r *RRMap) Get(rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, bool) {
	rrset, ok := r.Map[RRKey{rrtype, rrclass}]
	return rrset, ok
}

// Copy creates a copy of r. The data of the actual records are not copied.
func (r *RRMap) Copy() *RRMap {
	n := NewRRMap()
	for k, v := range r.Map {
		if v != nil {
			n.Map[k] = v.Copy()
		}
	}
	n.Exclusive = r.Exclusive
	return n
}

// Set replaces or deletes an rrset by type and class.
func (r *RRMap) Set(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) {
	key := RRKey{rrtype, rrclass}
	if rrset == nil {
		delete(r.Map, key)
	} else {
		r.Map[key] = rrset
	}
}

// Expire updates an RRMap backdating TTLs of surviving records and deleting others
func (r *RRMap) Expire(now time.Time) bool {
	for k, v := range r.Map {
		if v.Expire(now) {
			delete(r.Map, k)
		}
	}
	return len(r.Map) == 0
}

// Lookup returns matching RRSet entries.
// If exact is true, CNAMEs are not returned unless asked for.
func (r *RRMap) Lookup(exact bool, rrtype dns.RRType, rrclass dns.RRClass) *RRSet {
	var rrset *RRSet

	if !exact && rrclass != dns.AnyClass {
		rrset, _ = r.Get(dns.CNAMEType, rrclass)
		if rrset != nil {
			return rrset
		}
	}

	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		rrset = &RRSet{}
		for t, rs := range r.Map {
			if t.Match(exact, rrtype, rrclass) {
				rrset.Records = append(rrset.Records, rs.Records...)
			}
		}
		if len(rrset.Records) == 0 {
			rrset = nil
		}
	} else {
		rrset, _ = r.Get(rrtype, rrclass)
		if rrset != nil {
			rrset = rrset.Copy()
		}
	}

	return rrset
}

// Enter updates an RRMap with a new entry for the rrtype and rrclass.
// If rrtype is AnyType or rrclass is AnyClass, delete the matching entries.
func (r *RRMap) Enter(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error {
	if rrset != nil && len(rrset.Records) == 0 {
		rrset = nil
	}
	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		if rrset != nil {
			return ErrInvalidRRSet
		}
		for t := range r.Map {
			if t.Match(true, rrtype, rrclass) {
				delete(r.Map, t)
			}
		}
	} else {
		r.Set(rrtype, rrclass, rrset)
	}
	return nil
}

// Subtract removes records from r
// return true if the map was actually mutated
func (r *RRMap) Subtract(records []*dns.Record) bool {
	mutated := false
	for _, d := range records {
		if d.D != nil {
			key := RRKey{d.H.Type(), d.H.Class()}
			rrset, ok := r.Map[key]
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
				delete(r.Map, key)
			} else {
				r.Map[key] = &RRSet{
					Entered: rrset.Entered,
					Records: nr,
				}
			}
		} else {
			for key, _ := range r.Map {
				if key.Match(true, d.H.Type(), d.H.Class()) {
					mutated = true
					delete(r.Map, key)
				}
			}
		}
	}
	return mutated
}

// Merge adds records from n
func (r *RRMap) Merge(n *RRMap) {
	r.Exclusive = r.Exclusive || n.Exclusive
	for k, v := range n.Map {
		rs, ok := r.Map[k]
		if !ok {
			r.Map[k] = n.Map[k].Copy()
		} else {
			rs.Merge(v.Records)
		}
	}
}

// Load enters a series of records into the map
// entries with TTL 0 will be modified to TTL 1
func (r *RRMap) Load(entered time.Time, records []*dns.Record) bool {
	added := false
	n := NewRRMap()
	for _, rr := range records {
		key := RRKey{rr.H.Type(), rr.H.Class()}
		rrset, ok := n.Map[key]
		if !ok {
			rrset = &RRSet{Entered: entered}
			n.Map[key] = rrset
		}
		if rr.H.TTL() < time.Second {
			rr.H.SetTTL(time.Second)
		}
		if !r.Exclusive && dns.CacheFlush(rr.H) {
			r.Exclusive = true
		}
		rrset.Records = append(rrset.Records, rr)
	}
	for k, v := range n.Map {
		rrset, ok := r.Map[k]
		if !ok {
			r.Map[k] = v
			added = true
		} else {
			if rrset.Entered.IsZero() && !entered.IsZero() {
				continue
			}
			if r.Exclusive {
				r.Map[k] = v
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
	nr := &RRSet{Entered: rs.Entered}
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
