package resolver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
)

var ErrSOA = errors.New("SOA records cannot be interface specific")
var ErrIxfr = errors.New("SOA does not match for IXFR")
var ErrAxfr = errors.New("Mismatched or unexpected SOA values")
var ErrNoSOA = errors.New("zone has no SOA record")
var ErrNoKey = errors.New("zone has no record with this key")

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
	Enter(records []*dns.Record)
}

// the Authority interface defines a container finding closest a matching ZoneAuthority for a given Name
type Authority interface {
	Find(name dns.Name) ZoneAuthority
}

// the UpdateLog interface hooks zone updates.
type UpdateLog interface {
	// if Update returns an error, the update does not occur and the error is returned to the caller of the zone's update
	Update(key string, update []*dns.Record) error
}

type snapshot struct {
	soa         *dns.Record
	remove, add *Cache // all in 'add' if not differential
	prior       *snapshot
}

func (s *snapshot) serial() uint32 {
	return s.soa.D.(*dns.SOARecord).Serial
}

func (s *snapshot) collapse() *Cache {
	if s.prior == nil {
		if s.remove != nil {
			panic("snapshot is not differential but remove != nil")
		}
		return s.add
	}

	base := s.prior.collapse()
	base.Patch(s.remove, s.add)
	return base
}

func (s *snapshot) xfer(from *snapshot, rrclass dns.RRClass, next func(*dns.Record) error) error {
	if s.prior != from {
		if err := s.prior.xfer(from, rrclass, next); err != nil {
			return err
		}
	}

	if err := next(s.prior.soa); err != nil {
		return err
	}
	if err := s.remove.Enumerate(rrclass, next); err != nil {
		return err
	}
	if err := next(s.soa); err != nil {
		return err
	}
	if err := s.add.Enumerate(rrclass, next); err != nil {
		return err
	}

	return nil
}

// the Zone type holds authoritative records for a given DNS zone.
// Records in a zone may further be keyed by interface name.
type Zone struct {
	UpdateLog UpdateLog

	name      dns.Name
	hint      bool
	lk        sync.RWMutex
	snaplk    sync.Mutex // overlaps with lk; lock lk first!
	updated   bool
	soa       *dns.Record
	keys      map[string]*Cache
	snapshots map[string]*snapshot
	db, cache *Cache
}

// NewZone creates a new zone with a given name
func NewZone(name dns.Name, hint bool) *Zone {
	zone := &Zone{
		name:      name,
		hint:      hint,
		keys:      make(map[string]*Cache),
		snapshots: make(map[string]*snapshot),
	}
	zone.db = NewCache(nil)
	zone.cache = zone.db.Root()
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
// Load is usually performed on an off line zone.
func (z *Zone) Load(key string, clear bool, next func() (*dns.Record, error)) error {
	z.lk.Lock()
	defer z.lk.Unlock()

	db, ok := z.keys[key]
	if !ok {
		db = NewCache(z.db)
		z.keys[key] = db
	}

	if clear {
		db.Clear(true)
	}

	records := []*dns.Record{}
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
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	db.Enter(time.Time{}, false, records)
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
	data := db.Clone(true, nil)
	z.lk.RUnlock()

	if err := next(soa); err != nil {
		return err
	}
	return data.Enumerate(dns.AnyClass, next)
}

// Encode calls Save using codec as convenience
func (z *Zone) Encode(key string, c dns.Codec) error {
	return z.Save(key, func(r *dns.Record) error {
		return c.Encode(r)
	})
}

// Retrieve SOA data.
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

		update := []*dns.Record{r}
		z.db.Enter(time.Time{}, false, update)
		if z.UpdateLog != nil {
			z.UpdateLog.Update("", update)
		}
	}

	return r
}

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

func (z *Zone) Class() dns.RRClass {
	z.lk.RLock()
	defer z.lk.RUnlock()
	if z.soa == nil {
		return dns.InvalidClass
	}
	return z.soa.Class()
}

// Lookup a name within a zone, or a delegation above it.
func (z *Zone) Lookup(
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (a []*dns.Record, ns []*dns.Record, err error) {
	now := time.Now()
	z.lk.RLock()

	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}

	a, err = db.Get(now, name, rrtype, rrclass)
	if len(a) == 0 {
		for sname := name; sname.HasSuffix(z.name); sname = sname.Suffix() {
			if !z.hint && len(sname) == len(z.name) {
				// we can stop here if we're authoritative
				break
			}
			ns, _ = db.Get(now, sname, dns.NSType, rrclass)
			if len(ns) > 0 {
				err = nil
			}
			if len(ns) > 0 || len(sname) == 0 {
				// either have delegation or have reached dot
				break
			}
		}
	}

	z.lk.RUnlock()
	return
}

// SharedUpdate does an mdns record update, paying attention to CacheFlush
// If now is the zero value, the given records are owned by the caller. Any such records with the cache flush bit set
// will cause a panic.
// NSEC records matching their own name will be translated into the appropriate negative cache entries.
func (z *Zone) SharedUpdate(now time.Time, key string, records []*dns.Record) {
	z.lk.Lock()
	defer z.lk.Unlock()

	db, ok := z.keys[key]
	if !ok {
		db = NewCache(z.db)
		z.keys[key] = db
	}

	if now.IsZero() {
		// easy case: these are our own records. Just put them in and we are done.
		db.Enter(time.Time{}, false, records)
		return
	}

	// sift into three categories: negative cache, shared, exclusive
	var shared, exclusive, negative []*dns.Record
	for _, r := range records {
		if nsec, ok := r.D.(*dns.NSECRecord); ok && nsec.Next.Equal(r.Name()) {
			rrtype := nsec.Types.Next(dns.InvalidType)
			for rrtype != dns.InvalidType {
				negative = append(negative, &dns.Record{
					H: dns.NewHeader(r.Name(), rrtype, r.Class(), r.H.TTL()),
				})
				rrtype = nsec.Types.Next(rrtype)
			}
		} else {
			if m, ok := r.H.(*dns.MDNSHeader); ok && m.CacheFlush() {
				exclusive = append(exclusive, r)
			} else {
				shared = append(shared, r)
			}
		}
	}

	// do the updates
	if len(negative) > 0 {
		db.Enter(now, false, negative)
	}
	if len(shared) > 0 {
		db.Enter(now, true, shared)
	}
	if len(exclusive) > 0 {
		db.Enter(now, false, exclusive)
	}
}

// Enter calls the cache's Enter method for the cache layer under this zone. As this is not an mdns operation, there
// is no shared option and the current time is used.
// XXX do not cache pseduo records
func (z *Zone) Enter(records []*dns.Record) {
	z.lk.Lock()
	z.cache.Enter(time.Now(), false, records)
	z.lk.Unlock()
}

// Dump returns all records for a zone, optionally since a given soa.
// If serial is 0 or the zone does not have history for serial, a full result set is returned, otherwise an incremental result.
// The current serial will be snapshotted for future history if it was not already.
func (z *Zone) Dump(serial uint32, key string, rrclass dns.RRClass, next func(*dns.Record) error) (uint32, error) {
	var toSerial uint32

	z.lk.Lock()
	soa := z.soa_locked()
	if soa == nil {
		z.lk.Unlock()
		return 0, ErrNoSOA
	}
	toSerial = soa.D.(*dns.SOARecord).Serial
	db, ok := z.keys[key]
	if !ok {
		key = ""
		db = z.db
	}

	z.snaplk.Lock()
	defer z.snaplk.Unlock()

	snap, ok := z.snapshots[key]
	if !ok || snap.serial() != soa.D.(*dns.SOARecord).Serial {
		prior := snap

		var remove, add *Cache

		if prior != nil {
			// keep history clean to a maximum of 5 differentials
			i := 0
			p := prior
			for p != nil && i < 5 {
				i++
				p = p.prior
			}
			if p != nil && p.prior != nil {
				p.add = p.collapse()
				p.remove = nil
				p.prior = nil
			}

			last := prior.collapse()
			remove = last.Clone(false, db)
			add = db.Clone(false, last)
		} else {
			add = db.Clone(false, nil)
		}

		snap = &snapshot{
			soa:    soa,
			remove: remove,
			add:    add,
			prior:  prior,
		}
		z.snapshots[key] = snap
	}

	var from *snapshot
	var data *Cache

	if serial != 0 {
		from = snap
		for from != nil && from.serial() != serial {
			from = from.prior
		}
		if from == snap {
			from = nil
		} else if from == nil {
			data = db.Clone(false, nil)
		}
	} else {
		data = db.Clone(false, nil)
	}
	z.lk.Unlock() // done holding on to the zone data; can now answer queries while transferring. snapshots still locked

	if err := next(soa); err != nil {
		return toSerial, err
	}

	if from != nil {
		if err := snap.xfer(from, rrclass, next); err != nil {
			return toSerial, err
		}
		if err := next(soa); err != nil {
			return toSerial, err
		}
	} else if data != nil {
		if err := data.Enumerate(rrclass, next); err != nil {
			return toSerial, err
		}
		if err := next(soa); err != nil {
			return toSerial, err
		}
	}

	return toSerial, nil
}

// Xfer parses a zone transfer.
// Set ixfr to true or false to set axfr vs ixfr expectations
// If ixfr is false, the zone is cleared.
func (z *Zone) Xfer(ixfr bool, nextRecord func() (*dns.Record, error)) error {
	z.lk.RLock()

	var db *Cache
	if ixfr {
		db = z.db.Clone(false, nil)
	} else {
		db = NewCache(nil)
	}
	soa := z.soa

	z.lk.RUnlock()

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

	var del, add *Cache
	records := make([]*dns.Record, 0, 256)
	for {
		rec, err := nextRecord()

		if rec != nil {
			if s, ok := rec.D.(*dns.SOARecord); ok {
				if del != nil && add != nil {
					// done with incremental section

					add.Enter(time.Time{}, false, records)
					records = records[:0]

					db.Patch(del, add)
					del = nil
					add = nil
				}

				if del == nil {
					// any records here are normal xfer
					db.Enter(time.Time{}, false, records)
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
					del = NewCache(nil)
				} else {
					// start of add part of incremental section

					del.Enter(time.Time{}, false, records)
					records = records[:0]

					add = NewCache(nil)
					soa = rec
				}
			} else {
				records = append(records, rec)

				if len(records) >= cap(records) && del == nil && add == nil {
					// flush out the normal xfer records
					db.Enter(time.Time{}, false, records)
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

	// done!
	db.Enter(time.Time{}, false, []*dns.Record{soa})

	z.lk.Lock()
	z.soa = soa
	z.db = db

	for k, _ := range z.keys {
		delete(z.keys, k)
	}
	z.keys[""] = db

	z.lk.Unlock()
	return nil
}

// Update processes updates to a zone
func (z *Zone) Update(key string, prereq, update []*dns.Record) (bool, error) {
	now := time.Now()
	z.lk.Lock()
	defer z.lk.Unlock()

	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}

	soa := z.soa
	if soa == nil {
		return false, ErrNoSOA
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

		recs, _ := db.Get(now, r.Name(), rrtype, rrclass)
		match := len(recs) > 0
		if match && r.D != nil {
			match = false
			for _, rr := range recs {
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

	if z.UpdateLog != nil {
		if err := z.UpdateLog.Update(key, update); err != nil {
			return false, err
		}
	}

	for _, r := range update {
		name := r.Name()
		auth := name.Equal(z.name)
		rrtype, rrclass := r.Type(), r.Class()
		deleteSet := (rrclass == dns.NoneClass)
		if deleteSet {
			rrclass = soa.Class()
		}
		if deleteSet || r.D == nil {
			// allow removal of NS records not matching soa MName
			// (this is a bit of a hack and departure from RFC 2136)
			if auth && rrtype == dns.NSType && r.D != nil &&
				!r.D.(dns.NSRecordType).NS().Equal(soa.D.(*dns.SOARecord).MName) {
				auth = false
			}
			updated = db.Remove(now, auth, &dns.Record{
				H: dns.NewHeader(r.Name(), rrtype, rrclass, 0),
				D: r.D,
			})
		} else {
			rrset, _ := db.Get(now, name, rrtype, rrclass)
			found := false
			for _, rr := range rrset {
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
					rrset = nil // update replaces the only one
					z.soa = r

				case dns.WKSType:
					w1 := rr.D.(*dns.WKSRecord)
					w2 := r.D.(*dns.WKSRecord)
					if w1.Protocol == w2.Protocol && bytes.Compare(w1.Address[:], w2.Address[:]) == 0 {
						found = true
					}

				case dns.CNAMEType:
					// like SOA and tiggers, there can only be one
					if rr.D.Equal(r.D) {
						found = true
					}
					rrset = nil

				default:
					if rr.D.Equal(r.D) {
						found = true
					}
				}
			}
			if found {
				// skip existing or matching record
				continue
			}
			rrset = append(rrset, r)
			db.Enter(time.Time{}, false, rrset)
			updated = true
		}
	}

	// unless we updated the soa, mark zone updated (if it updated)
	if z.soa == soa || z.soa.Equal(soa) {
		z.updated = z.updated || updated
	} else {
		z.updated = false
	}

	return updated, nil
}
