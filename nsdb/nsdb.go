package nsdb

import (
	"errors"
	"time"

	"tessier-ashpool.net/dns"
)

var ErrInvalidRRSet = errors.New("invalid rrset")
var ErrAlreadyUpdating = errors.New("already in update context")
var ErrNotUpdating = errors.New("no update context")

// the RRSet type is a value for a given name, type and class
type RRSet struct {
	Entered time.Time
	Records []*dns.Record
}

// the Db interface defines an instance of a database back end.
// After storing or retrieving an *RRset instance, use RRSet.Copy to make a mutable shallow copy if it will be modified.
type Db interface {
	// Lookup returns an RRSet. If not records exist for the name regardless of type, returns NXDomain. If the
	// name exists but not of the type, no error is returned.
	// Empty RRSets are never returned, so existence check is simply a check against nil.
	// If exact is false, rrtype may be AnyType or rrclass may be AnyClass, and a combined record set may be returned,
	// and records having a CNAME matching the class will also be returned (DNS lookup rules).
	// if exact is true, rrtype may be AnyType or rrclass may be AnyClass, but CNAMEs are not returned unless asked for.
	// CAUTION: the returned RRSet and its record slice should be treated as immutable
	Lookup(exact bool, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error)

	// Enter replaces an RRSet for a given type and class. If rrset is nil, the entry is deleted.
	// If rrset is nil and rrtype is Any or rrclass is Any, all matching records will be deleted.
	// CAUTION: the database instance takes over ownership of ths rrset and its record slice.
	Enter(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error

	// Snapshot snapshots the database at a given serial number. If not supported, Snapshot does nothing and
	// returns no error
	Snapshot(serial uint32) error

	// Enumerate returns all records in the database. If starting serial is not found or backend does not
	// support snapshotting, a full set is returned, indicated by the serial parameter in f set to 0.
	// If snapshotted, result will be a delta to current, with serial indicating records to be removed.
	Enumerate(serial uint32, f func(serial uint32, records []*dns.Record) error) error

	// Begins an update transaction. There can be only one
	BeginUpdate() error

	// Commits the update transaction
	EndUpdate(abort bool) error

	// Clear resets the database.
	// XXX This method presumes populating from a zone file, which will ultimately be handled by the backend
	Clear() error
}

// Load is a convenience function to load up a batch of records to throw in to the database.
// The slice of records will end up sorted.
func Load(db Db, entered time.Time, records []*dns.Record) (bool, error) {
	added := false
	err := dns.RecordSets(
		records,
		func(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, records []*dns.Record) error {
			rrset, err := db.Lookup(true, name, rrtype, rrclass)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return err
			}
			if rrset != nil && rrset.Entered.IsZero() && !entered.IsZero() {
				// do not molest permanent records
				return nil
			}

			if rrset == nil {
				rrset = &RRSet{
					Entered: entered,
					Records: make([]*dns.Record, len(records)),
				}
				copy(rrset.Records, records)
				added = true
			} else {
				rrset = rrset.Copy()
				olen := len(rrset.Records)
				rrset.Merge(records)
				added = added || olen != len(rrset.Records)
			}

			return db.Enter(name, rrtype, rrclass, rrset)
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
		func(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, records []*dns.Record) error {
			rrset, err := db.Lookup(true, name, rrtype, rrclass)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return err
			}
			if rrset != nil {
				olen := len(rrset.Records)
				rrset = rrset.Copy()
				if rrset.Subtract(records) {
					rrset = nil
					updated = true
				} else {
					updated = updated || olen != len(rrset.Records)
				}
				if err := db.Enter(name, rrtype, rrclass, rrset); err != nil {
					return err
				}
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
	var nr []*dns.Record

	for _, or := range rs.Records {
		found := false
		for _, rr := range records {
			if rr.D == nil || or.D.Equal(rr.D) {
				found = true
				break
			}
		}
		if !found {
			nr = append(nr, or)
		}
	}
	rs.Records = nr
	return len(nr) == 0
}

// Copy creates a new RRSet shallow copy
func (rs *RRSet) Copy() *RRSet {
	nr := &RRSet{Entered: rs.Entered}
	nr.Records = make([]*dns.Record, len(rs.Records))
	copy(nr.Records, rs.Records)
	return nr
}
