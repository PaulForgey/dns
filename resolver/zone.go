package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/nsdb"
)

var ErrSOA = errors.New("SOA records cannot be interface specific")
var ErrIxfr = errors.New("SOA does not match for IXFR")
var ErrAxfr = errors.New("Mismatched or unexpected SOA values")
var ErrNoSOA = errors.New("zone has no SOA record")
var ErrNoKey = errors.New("zone has no record with this key")
var ErrXferInProgress = errors.New("zone is already transferring")

// the ZoneAuthority interface tells a resolver how to look up authoritative records or delegations
type ZoneAuthority interface {
	// Lookup retrieves authoritative records for the zone, or cached entries if they were entered
	Lookup(key string, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (a []*dns.Record, ns []*dns.Record, err error)
	// Hint returns true if this is a hint zone
	Hint() bool
	// Name returns the name of the zone
	Name() dns.Name
	// SOA returns the zone's SOA record, may return nil
	SOA() *dns.Record
	// Enter enters recors into the cache (usually only makes sense with hint zones)
	Enter(records []*dns.Record) error
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
	UpdateLog UpdateLog

	name     dns.Name
	hint     bool
	lk       sync.RWMutex
	xferlock int32
	updated  bool
	soa      *dns.Record
	keys     map[string]nsdb.Db
	db       nsdb.Db
	cache    *nsdb.Cache
}

// NewZone creates a new zone with a given name
func NewZone(name dns.Name, hint bool) *Zone {
	zone := &Zone{
		name: name,
		hint: hint,
		keys: make(map[string]nsdb.Db),
	}
	zone.db = nsdb.NewMemory() // XXX while we load from files through the front end
	zone.cache = nsdb.NewCache()
	zone.keys[""] = zone.db
	return zone
}

func (z *Zone) Hint() bool {
	return z.hint
}

func (z *Zone) Name() dns.Name {
	return z.name
}

// Load loads in a series of records. If an SOA is found, the later in the sequence is used to update serial.
// next returns nil, io.EOF on last record
// XXX this belongs in ns.Zone, but stays here while we load through the front end. resolver.Zone needs to
//     create a hint zone
func (z *Zone) Load(key string, clear bool, next func() (*dns.Record, error)) error {
	z.lk.Lock()
	defer z.lk.Unlock()

	db, ok := z.keys[key]
	if !ok {
		db = nsdb.NewMemory()
		z.keys[key] = db
	}

	if clear {
		db.Clear()
	}

	records := make([]*dns.Record, 0, 256)
	for {
		rec, err := next()
		if rec != nil {
			if !rec.Name().HasSuffix(z.name) {
				return fmt.Errorf("%w: name=%v, suffix=%v", dns.NotZone, rec.Name(), z.name)
			}
			if rec.Type() == dns.SOAType {
				if key != "" {
					return ErrSOA
				}
				if _, ok := rec.D.(*dns.SOARecord); ok {
					z.soa = rec
				}
			}
			records = append(records, rec)
			if len(records) == cap(records) {
				if _, err := nsdb.Load(db, time.Time{}, records); err != nil {
					return err
				}
				records = records[:0]
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}
	if len(records) > 0 {
		if _, err := nsdb.Load(db, time.Time{}, records); err != nil {
			return err
		}
	}

	return nil
}

// Decode calls Load using a codec as a convenience
func (z *Zone) Decode(key string, clear bool, c dns.Codec) error {
	return z.Load(key, clear, func() (*dns.Record, error) {
		r := &dns.Record{}
		if err := c.Decode(r); err != nil {
			return nil, err
		}
		return r, nil
	})
}

// Save writes a shallow copy of the zone for the given key
// XXX this belongs in ns.Zone
func (z *Zone) Save(key string, next func(r *dns.Record) error) error {
	z.lk.RLock()
	soa := z.soa
	if soa == nil {
		z.lk.RUnlock()
		return ErrNoSOA
	}
	for z.updated {
		// insure we are left holding a read lock with up to date SOA
		z.lk.RUnlock()
		z.lk.Lock()
		soa = z.soa_locked()
		z.lk.Unlock()
		z.lk.RLock()
	}
	db, ok := z.keys[key]
	if !ok {
		z.lk.RUnlock()
		return ErrNoKey // this is a shallow operation, so wrong key is an error
	}
	z.lk.RUnlock()

	if soa != nil {
		if err := next(soa); err != nil {
			return err
		}
	}
	if err := db.Enumerate(0, func(serial uint32, records []*dns.Record) error {
		for _, r := range records {
			if r.Type() != dns.SOAType {
				if err := next(r); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}

	return nil
}

// Encode calls Save using codec as convenience
// XXX this belongs in ns.Zone
func (z *Zone) Encode(key string, c dns.Codec) error {
	return z.Save(key, func(r *dns.Record) error {
		return c.Encode(r)
	})
}

func (z *Zone) soa_locked() *dns.Record {
	r := z.soa

	if r != nil && z.updated {
		soa := r.D.(*dns.SOARecord)
		nsoa := dns.SOARecord(*soa)
		soa = &nsoa
		r = &dns.Record{
			H: r.H,
			D: soa,
		}
		soa.Serial++

		z.updated = false
		z.soa = r

		update := &nsdb.RRSet{Records: []*dns.Record{r}}
		z.db.Enter(r.Name(), r.Type(), r.Class(), update)
		if z.UpdateLog != nil {
			z.UpdateLog.Update("", update.Records)
		}
	}

	return r
}

// Retrieve SOA data.
// XXX this belongs in ns.Zone
func (z *Zone) SOA() *dns.Record {
	var r *dns.Record

	z.lk.RLock()
	r = z.soa
	if r != nil && z.updated {
		z.lk.RUnlock()
		z.lk.Lock()
		r = z.soa_locked()
		z.lk.Unlock()
	} else {
		z.lk.RUnlock()
	}
	return r
}

// Class returns the class for the zone.
// XXX this belongs in ns.Zone
func (z *Zone) Class() dns.RRClass {
	z.lk.RLock()
	rrclass := dns.InvalidClass
	if z.soa != nil {
		rrclass = z.soa.Class()
	}
	z.lk.RUnlock()
	return rrclass
}

// Lookup a name within a zone, or a delegation above it.
func (z *Zone) Lookup(
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	z.lk.RLock()
	db, keyed := z.keys[key]
	if !keyed {
		db = z.db
	}
	z.lk.RUnlock()

	// first check the cache
	a, ns, err := z.lookup(z.cache, name, rrtype, rrclass)
	if err != nil && !errors.Is(err, dns.NXDomain) {
		return nil, nil, err
	}

	if len(a) == 0 && db != z.cache {
		// then our database
		a, ns, err = z.lookup(db, name, rrtype, rrclass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, nil, err
		}

		if len(a) == 0 && keyed {
			// and if keyed, the main db (this has final delegation authority)
			a, ns, err = z.lookup(z.db, name, rrtype, rrclass)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return nil, nil, err
			}
		}
	}

	return a, ns, err
}

func (z *Zone) lookup(
	db nsdb.Db,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	rrset, err := db.Lookup(false, name, rrtype, rrclass)
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

		rrset, nsset, err2 := z.lookup(db, name, dns.NSType, rrclass)
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

// Enter calls the cache's Enter method for the cache layer under this zone. As this is not an mdns operation, there
// is no shared option and the current time is used.
// XXX do not cache pseduo records
func (z *Zone) Enter(records []*dns.Record) error {
	_, err := nsdb.Load(z.cache, time.Now(), records)
	return err
}

// Dump returns all records for a zone, optionally since a given soa.
// If serial is 0 or the zone does not have history for serial, a full result set is returned, otherwise an incremental result.
// The current serial will be snapshotted for future history if it was not already.
// XXX this belongs in ns.Zone
func (z *Zone) Dump(serial uint32, rrclass dns.RRClass, next func(*dns.Record) error) (uint32, error) {
	var toSerial uint32

	z.lk.Lock()

	soa := z.soa_locked()
	if soa == nil {
		z.lk.Unlock()
		return 0, ErrNoSOA
	}
	soaD := soa.D.(*dns.SOARecord)
	toSerial = soaD.Serial
	fromSOA := &dns.Record{
		H: soa.H,
		D: &dns.SOARecord{
			MName:   soaD.MName,
			ReName:  soaD.ReName,
			Serial:  serial,
			Refresh: soaD.Refresh,
			Retry:   soaD.Retry,
			Expire:  soaD.Expire,
			Minimum: soaD.Minimum,
		},
	}
	toSOA := soa

	z.lk.Unlock()

	if err := next(soa); err != nil {
		return toSerial, err
	}

	if serial == toSerial {
		return toSerial, nil
	}

	if err := z.db.Snapshot(soaD.Serial); err != nil {
		return toSerial, err
	}

	err := z.db.Enumerate(serial, func(serial uint32, records []*dns.Record) error {
		if serial != 0 && fromSOA != nil {
			if err := next(fromSOA); err != nil {
				return err
			}
			fromSOA = nil
		}
		if serial == 0 && toSOA != nil {
			if fromSOA == nil {
				if err := next(toSOA); err != nil {
					return err
				}
			}
			toSOA = nil
		}
		for _, r := range records {
			if r.Type() == dns.SOAType {
				continue
			}
			if err := next(r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return toSerial, err
	}
	if err = next(soa); err != nil {
		return toSerial, err
	}

	return toSerial, nil
}

// Xfer parses a zone transfer.
// Set ixfr to true or false to set axfr vs ixfr expectations
// If ixfr is false, the zone is cleared.
// XXX this belongs in ns.Zone
func (z *Zone) Xfer(ixfr bool, nextRecord func() (*dns.Record, error)) error {
	var db nsdb.Db
	abort := true

	z.lk.RLock()

	defer func() {
		if db != nil {
			db.EndUpdate(abort)
		}
		atomic.AddInt32(&z.xferlock, -1)
		z.lk.RUnlock()
	}()

	if atomic.AddInt32(&z.xferlock, 1) > 1 {
		return ErrXferInProgress
	}

	soa := z.soa
	toSOA, err := nextRecord()
	if err != nil {
		return err
	}

	_, ok := toSOA.D.(*dns.SOARecord)
	if !ok {
		return fmt.Errorf("%w: expected SOA, got %T", ErrAxfr, soa.D)
	}
	if soa == nil {
		// we have no existing data to know better
		soa = toSOA
	}

	if err := z.db.BeginUpdate(); err != nil {
		return err
	}
	db = z.db

	var del, add []*dns.Record
	records := make([]*dns.Record, 0, 256)
	for {
		rec, err := nextRecord()

		if rec != nil {
			if s, ok := rec.D.(*dns.SOARecord); ok {
				if del != nil && add != nil {
					// done with incremental section

					add = append(add, records...)
					records = records[:0]

					if _, err := nsdb.Patch(z.db, del, add); err != nil {
						return err
					}

					del = nil
					add = nil
				}

				if del == nil {
					// any records here are normal xfer
					if _, err := nsdb.Load(z.db, time.Time{}, records); err != nil {
						return err
					}
					records = records[:0]

					// if this soa is toSOA, we're done
					if s.Serial == toSOA.D.(*dns.SOARecord).Serial {
						soa = rec
						break
					}

					// start of next incremental section or end of axfr
					if s.Serial != soa.D.(*dns.SOARecord).Serial {
						return fmt.Errorf(
							"%w: got serial %d, at serial %d",
							ErrIxfr,
							s.Serial,
							soa.D.(*dns.SOARecord).Serial,
						)
					}

					soa = rec
					del = make([]*dns.Record, 0)
				} else {
					// start of add part of incremental section

					del = append(del, records...)
					records = records[:0]

					add = make([]*dns.Record, 0)
					soa = rec
				}
			} else {
				records = append(records, rec)

				if len(records) >= cap(records) && del == nil && add == nil {
					// flush out the normal xfer records
					if _, err := nsdb.Load(z.db, time.Time{}, records); err != nil {
						return err
					}
					records = records[:0]
				}
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	if soa.D.(*dns.SOARecord).Serial != toSOA.D.(*dns.SOARecord).Serial {
		return fmt.Errorf(
			"%w: final SOA response at serial %d, not %d",
			ErrAxfr,
			soa.D.(*dns.SOARecord).Serial,
			toSOA.D.(*dns.SOARecord).Serial,
		)
	}

	if err := z.db.Enter(soa.Name(), dns.SOAType, soa.Class(), &nsdb.RRSet{Records: []*dns.Record{soa}}); err != nil {
		return err
	}

	// done!
	abort = false
	z.soa = soa // XXX potential data race (read lock)
	return nil
}

// Update processes updates to a zone
// XXX this belongs in ns.Zone
func (z *Zone) Update(key string, prereq, update []*dns.Record) (bool, error) {
	var db nsdb.Db
	var ok bool

	abort := true

	z.lk.Lock()
	defer func() {
		z.lk.Unlock()
		if db != nil {
			db.EndUpdate(abort)
		}
	}()

	soa := z.soa
	if soa == nil {
		return false, ErrNoSOA
	}

	db, ok = z.keys[key]
	if !ok {
		db = z.db
	}
	if err := db.BeginUpdate(); err != nil {
		db = nil
		return false, err
	}

	// process the prereq
	for _, r := range prereq {
		if !r.Name().HasSuffix(z.name) {
			return false, dns.NotZone
		}
		rrtype, rrclass := r.Type(), r.Class()
		exclude := (rrclass == dns.NoneClass)
		if exclude {
			rrclass = dns.AnyClass
		}
		if (rrtype == dns.AnyType || rrclass == dns.AnyClass) && r.D != nil {
			return false, dns.FormError
		}

		rrset, _ := db.Lookup(false, r.Name(), rrtype, rrclass)
		match := rrset != nil
		if match && r.D != nil {
			match = false
			for _, rr := range rrset.Records {
				if rr.Type() != rrtype { // should only happen for CNAME not being looked for
					break
				}
				if rr.D.Equal(r.D) {
					match = true
					break
				}
			}
		}

		if match && exclude {
			if rrtype == dns.AnyType {
				return false, dns.YXDomain
			} else {
				return false, dns.YXRRSet
			}
		} else if !match && !exclude {
			if rrtype == dns.AnyType {
				return false, dns.NXDomain
			} else {
				return false, dns.NXRRSet
			}
		}
	}

	// check the updates
	for _, r := range update {
		if !r.Name().HasSuffix(z.name) {
			return false, dns.NotZone
		}
		rrtype, rrclass := r.Type(), r.Class()
		if (rrtype == dns.AnyType || rrclass == dns.AnyClass) && r.D != nil {
			return false, dns.FormError
		}
		deleteSet := (rrclass == dns.NoneClass)
		if deleteSet {
			if r.D == nil {
				return false, dns.FormError
			}
		} else if (rrtype != dns.AnyType && rrclass != dns.AnyClass) && r.D == nil {
			return false, dns.FormError
		}
	}

	// do the updates
	updated := false

	for _, r := range update {
		name, rrtype, rrclass := r.Name(), r.Type(), r.Class()
		auth := name.Equal(z.name)

		deleteSet := (rrclass == dns.NoneClass)
		if deleteSet {
			rrclass = soa.Class()
		}
		if deleteSet || r.D == nil {
			if auth && (rrtype == dns.NSType || rrtype == dns.SOAType) {
				continue
			}

			u, err := nsdb.Patch(
				db,
				[]*dns.Record{
					&dns.Record{
						H: dns.NewHeader(r.Name(), rrtype, rrclass, 0),
						D: r.D,
					},
				},
				nil,
			)
			if err != nil {
				return false, err
			}
			updated = updated || u
		} else {
			if rrclass == dns.AnyClass {
				rrclass = soa.Class()
			}

			rrset, err := db.Lookup(false, name, rrtype, rrclass)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return false, err
			}

			var update *nsdb.RRSet
			if rrset != nil {
				update = rrset.Copy()
			} else {
				update = &nsdb.RRSet{}
			}

			found := false
			if rrset != nil {
				for _, rr := range rrset.Records {
					if found {
						break
					}
					if rr.Type() != rrtype {
						found = true // CNAME and not looking to update one
						break
					}
					switch rrtype {
					case dns.SOAType:
						if !rr.H.Equal(r.H) {
							found = true
							break
						}
						if rr.D.(*dns.SOARecord).Serial > r.D.(*dns.SOARecord).Serial {
							found = true
							break
						}
						update.Records = nil // update replaces the only one
						z.soa = r

					case dns.WKSType:
						w1 := rr.D.(*dns.WKSRecord)
						w2 := r.D.(*dns.WKSRecord)
						if w1.Protocol == w2.Protocol &&
							bytes.Compare(w1.Address[:], w2.Address[:]) == 0 {
							found = true
						}

					case dns.CNAMEType:
						// like SOA and tiggers, there can only be one
						if rr.D.Equal(r.D) {
							found = true
						}
						update.Records = nil

					default:
						if rr.D.Equal(r.D) {
							found = true
						}
					}
				}
			}
			if found {
				// skip existing or matching record
				continue
			}
			update.Records = append(update.Records, r)
			if err := db.Enter(name, rrtype, rrclass, update); err != nil {
				return false, err
			}
			updated = true
		}
	}

	if z.UpdateLog != nil {
		if err := z.UpdateLog.Update(key, update); err != nil {
			return false, err
		}
	}

	// unless we updated the soa, mark zone updated (if it updated)
	if z.soa == soa || z.soa.Equal(soa) {
		z.updated = z.updated || updated
	} else {
		z.updated = false
	}

	abort = false
	return updated, nil
}
