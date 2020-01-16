package nsdb

import (
	"errors"
	"sort"
	"time"

	"tessier-ashpool.net/dns"
)

// the RRSet type is a value for a given name, type and class
type RRSet struct {
	Entered time.Time // this value is opaque to the backend
	Records []*dns.Record
}

// the Db interface defines an instance of a database back end. Nothing at this level makes any interpretation of
// types or classes, e.g. AnyClass or AnyType have no meaning.
// After storing or retrieving an *RRset instance, use RRSet.Copy to make a mutable shallow copy if it will be modified.
type Db interface {
	// Lookup returns an RRSet. If not records exist for the name regardless of type, returns NXDomain. If the
	// name exists but not of the type, no error is returned.
	// CAUTION: the returned RRSet and its record slice should be treated as immutable
	Lookup(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error)

	// Enter replaces an RRSet for a given type and class. If rrset is nil, the entry is deleted.
	// CAUTION: the database instance takes over ownership of ths rrset and its record slice.
	Enter(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error

	// Snapshot snapshots the database at a given serial number. If not supported, Snapshot does nothing and
	// returns no error
	Snapshot(serial uint32) error

	// Enumerate returns all records in the database. If starting serial is not found or backend does not
	// support snapshotting, a full set is returned, indicated by the serial parameter in f set to 0.
	// If snapshotted, result will be a delta to current, with serial indicating records to be removed.
	Enumerate(serial uint32, f func(serial uint32, records []*dns.Record) error) error
}

// Load is a convenience function to load up a batch of records to throw in to the database.
// The slice of records will end up sorted.
func Load(db Db, entered time.Time, records []*dns.Record) error {
	sort.Slice(records, func(i, j int) bool { return records[i].Less(records[j]) })

	var name dns.Name
	var rrtype dns.RRType
	var rrclass dns.RRClass

	enter := func(records []*dns.Record) error {
		rrset, err := db.Lookup(name, rrtype, rrclass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return err
		}

		if rrset == nil {
			rrset = &RRSet{
				Entered: entered,
				Records: make([]*dns.Record, len(records)),
			}
			copy(rrset.Records, records)
		} else {
			rrset = rrset.Copy()
			rrset.Records = append(rrset.Records, records...)
		}

		return db.Enter(name, rrtype, rrclass, rrset)
	}

	j := 0
	for i, r := range records {
		if !name.Equal(r.Name()) || rrtype != r.Type() || rrclass != r.Class() {
			if i > 0 {
				if err := enter(records[j:i]); err != nil {
					return err
				}
			}

			j = i
			name, rrtype, rrclass = r.Name(), r.Type(), r.Class()
		}
	}
	if err := enter(records[j:]); err != nil {
		return err
	}

	return nil
}

// Expire updates an RRSet backdating the TTLs and removing expired records
// If the RRSet has an zero Entered value, Expire does nothing
// If the entire RRSet goes away, Expire returns true to indicate it may be purged entirely
func (rs *RRSet) Expire(now time.Time) bool {
	if rs.Entered.IsZero() {
		return false
	}
	if now.Before(rs.Entered) {
		panic("time went backwards")
	}
	records := make([]*dns.Record, 0)
	since := now.Sub(rs.Entered)
	for _, r := range rs.Records {
		expires := rs.Entered.Add(r.H.TTL())
		if !now.Before(expires) { // now >= expires
			continue
		}

		// add the adjusted record back in to the replacement list
		records = append(records, &dns.Record{
			H: dns.NewHeader(r.H.Name(), r.H.Type(), r.H.Class(), r.H.TTL()-since),
			D: r.D,
		})
	}
	rs.Entered = now
	rs.Records = records
	return len(records) == 0
}

// Rotate rotates the records in an RRSet
func (rs *RRSet) Rotate() {
	if len(rs.Records) < 2 {
		return
	}
	r := rs.Records[0]
	copy(rs.Records, rs.Records[1:])
	rs.Records[len(rs.Records)-1] = r
}

// Merge combines two sets of records excluding duplicates
func (rs *RRSet) Merge(records []*dns.Record) {
	rs.Records = append(rs.Records, rs.Exclude(records)...)
}

// Exclude returns records not in rs
func (rs *RRSet) Exclude(records []*dns.Record) []*dns.Record {
	var nr []*dns.Record

	for _, rr := range records {
		found := false
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

// Copy creates a new RRSet shallow copy
func (rs *RRSet) Copy() *RRSet {
	nr := &RRSet{Entered: rs.Entered}
	nr.Records = make([]*dns.Record, len(rs.Records))
	copy(nr.Records, rs.Records)
	return nr
}
