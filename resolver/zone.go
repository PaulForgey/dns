package resolver

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
)

var ErrMartian = errors.New("record does not have suffix of zone")
var ErrSOA = errors.New("SOA records cannot be interface specific")
var ErrIxfr = errors.New("SOA does not match for IXFR")
var ErrAxfr = errors.New("Mismatched or unexpected SOA values")

type snapshot struct {
	soa         *dns.Record
	remove, add *Cache // all in 'add' if not differential
	prior       *snapshot
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

func (s *snapshot) xfer(from *snapshot) []*dns.Record {
	var records []*dns.Record

	if s.prior != from {
		records = append(records, s.prior.xfer(from)...)
	}

	records = append(records, s.prior.soa)
	s.remove.Enumerate(func(r *dns.Record) {
		records = append(records, r)
	})
	records = append(records, s.soa)
	s.add.Enumerate(func(r *dns.Record) {
		records = append(records, r)
	})

	return records
}

// the Zone type holds authoritative records for a given DNS zone.
// Records in a zone may further be keyed by interface name.
type Zone struct {
	Name dns.Name // domain name of the zone
	Hint bool     // zone is only a hint for caching and is not authoritative

	lk        sync.RWMutex
	updated   bool
	soa       *dns.Record
	keys      map[string]*Cache
	snapshots map[string]*snapshot
	db, cache *Cache
}

// the Zones type holds all the zones we know of
type Zones struct {
	sync.RWMutex
	zones map[string]*Zone
}

// NewZones creates an empty Zones
func NewZones() *Zones {
	return &Zones{
		zones: make(map[string]*Zone),
	}
}

// Insert adds or overwrites a zone
func (s *Zones) Insert(z *Zone) {
	s.Lock()
	s.zones[z.Name.Key()] = z
	s.Unlock()
}

// Finds a zone by name having the closest common suffix.
// Find can return nil if the root zone is not present.
func (s *Zones) Find(n dns.Name) *Zone {
	var z *Zone
	var ok bool

	s.RLock()

	for {
		z, ok = s.zones[n.Key()]
		if ok || len(n) == 0 {
			break
		}
		n = n.Suffix()
	}

	s.RUnlock()
	return z
}

// NewZone creates a new zone with a given name
func NewZone(name dns.Name) *Zone {
	zone := &Zone{
		Name:      name,
		keys:      make(map[string]*Cache),
		snapshots: make(map[string]*snapshot),
	}
	zone.db = NewCache(nil)
	zone.cache = zone.db.Root()
	zone.keys[""] = zone.db
	return zone
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
			if !rec.RecordHeader.Name.HasSuffix(z.Name) {
				return fmt.Errorf("%w: name=%v, suffix=%v", ErrMartian, rec.RecordHeader.Name, z.Name)
			}
			if rec.Type() == dns.SOAType {
				if key != "" {
					return ErrSOA
				}
				if _, ok := rec.RecordData.(*dns.SOARecord); ok {
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

// Retrieve SOA data.
func (z *Zone) SOA() *dns.SOARecord {
	var soa *dns.SOARecord

	z.lk.Lock()
	soa = z.soa.RecordData.(*dns.SOARecord)
	if z.updated {
		z.updated = false
		soa.Serial++
	}
	z.lk.Unlock()
	return soa
}

// Lookup a name within a zone, or a delegation above it.
func (z *Zone) Lookup(key string, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (a []*dns.Record, ns []*dns.Record) {
	now := time.Now()
	z.lk.RLock()

	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}

	for len(a) == 0 && len(ns) == 0 {
		a = db.Get(now, name, rrtype, rrclass)
		if len(a) == 0 {
			for sname := name; sname.HasSuffix(z.Name); sname = sname.Suffix() {
				if !z.Hint && len(sname) == len(z.Name) {
					// we can stop here if we're authoritative
					break
				}
				ns = db.Get(now, sname, dns.NSType, rrclass)
				if len(ns) > 0 || len(sname) == 0 {
					// either have delegation or have reached dot
					break
				}
			}
		}
		if db == z.db {
			break
		}
		db = z.db // this was keyed, now look unkeyed
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
	db, ok := z.keys[key]
	if !ok {
		db = NewCache(z.db)
		z.keys[key] = db
	}
	z.lk.Unlock()

	if now.IsZero() {
		// easy case: these are our own records. Just put them in and we are done.
		db.Enter(time.Time{}, false, records)
		return
	}

	// sift into three categories: negative cache, shared, exclusive
	var shared, exclusive, negative []*dns.Record
	for _, r := range records {
		if nsec, ok := r.RecordData.(*dns.NSECRecord); ok && nsec.Next.Equal(r.RecordHeader.Name) {
			rrtype := nsec.Types.Next(dns.InvalidType)
			for rrtype != dns.InvalidType {
				negative = append(negative, &dns.Record{
					RecordHeader: dns.RecordHeader{
						Name:  r.RecordHeader.Name,
						TTL:   r.RecordHeader.TTL,
						Type:  rrtype,
						Class: r.Class(),
					},
				})
				rrtype = nsec.Types.Next(rrtype)
			}
		} else {
			if r.CacheFlush {
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
func (z *Zone) Enter(records []*dns.Record) {
	z.lk.Lock()
	z.cache.Enter(time.Now(), false, records)
	z.lk.Unlock()
}

// Dump returns all records for a zone, optionally since a given soa.
// If serial is 0 or the zone does not have history for serial, a full result set is returned, otherwise an incremental result.
// The current serial will be snapshotted for future history.
func (z *Zone) Dump(serial uint32, key string) []*dns.Record {
	z.lk.Lock()
	soa := z.soa.RecordData.(*dns.SOARecord)
	if z.updated || soa.Serial == 0 {
		soa.Serial++
		z.updated = false
	}
	db, ok := z.keys[key]
	if !ok {
		key = ""
		db = z.db
	}
	snap, ok := z.snapshots[key]
	if !ok || snap.soa.RecordData.(*dns.SOARecord).Serial != soa.Serial {
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
			remove = last.Clone(db)
			add = db.Clone(last)
		} else {
			add = db.Clone(nil)
		}

		snap = &snapshot{
			soa: &dns.Record{
				RecordHeader: z.soa.RecordHeader,
				RecordData: &dns.SOARecord{
					MName:   soa.MName.Copy(),
					RName:   soa.RName.Copy(),
					Serial:  soa.Serial,
					Refresh: soa.Refresh,
					Retry:   soa.Retry,
					Expire:  soa.Expire,
					Minimum: soa.Minimum,
				},
			},
			remove: remove,
			add:    add,
			prior:  prior,
		}
		z.snapshots[key] = snap
	}

	var from *snapshot
	if serial != 0 {
		from = snap
		for from != nil && from.soa.RecordData.(*dns.SOARecord).Serial != serial {
			from = from.prior
		}
		if from == snap {
			from = nil
		}
	}

	records := []*dns.Record{z.soa}

	if from != nil {
		records = append(records, snap.xfer(from)...)
	} else {
		data := db.Clone(nil)
		data.Enumerate(func(r *dns.Record) {
			records = append(records, r)
		})
	}

	records = append(records, z.soa)
	z.lk.Unlock()
	return records
}

// Xfer parses a zone transfer.
// Set ixfr to true or false to set axfr vs ixfr expectations
// If ixfr is false, the zone is cleared.
func (z *Zone) Xfer(nextRecord func() (*dns.Record, error), ixfr bool) error {
	z.lk.Lock()
	defer z.lk.Unlock()

	var db *Cache
	if ixfr {
		db = z.db.Clone(nil)
	} else {
		db = NewCache(nil)
	}
	soa := z.soa

	toSOA, err := nextRecord()
	if err != nil {
		return err
	}

	_, ok := toSOA.RecordData.(*dns.SOARecord)
	if !ok {
		return fmt.Errorf("%w: expected SOA, got %T", ErrAxfr, soa.RecordData)
	}

	var del, add *Cache
	var records []*dns.Record
	for {
		rec, err := nextRecord()

		if rec != nil {
			if s, ok := rec.RecordData.(*dns.SOARecord); ok {
				if del != nil && add != nil {
					// done with increment section

					add.Enter(time.Time{}, false, records)
					records = nil

					db.Patch(del, add)
					del = nil
					add = nil
				}

				if del == nil {
					// start of next increment section or end of axfr
					if s.Serial != soa.RecordData.(*dns.SOARecord).Serial {
						return fmt.Errorf(
							"%w: got serial %d, at serial %d",
							ErrIxfr,
							s.Serial,
							soa.RecordData.(*dns.SOARecord).Serial,
						)
					}

					// any records here are normal xfer
					db.Enter(time.Time{}, false, records)
					records = nil

					del = NewCache(nil)
					soa = rec
				} else {
					// start of add part of incremental section

					del.Enter(time.Time{}, false, records)
					records = nil

					add = NewCache(nil)
					soa = rec
				}
			} else {
				records = append(records, rec)

				if len(records) > 256 && del == nil && add == nil {
					// flush out the normal xfer records
					db.Enter(time.Time{}, false, records)
					records = nil
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

	if soa.RecordData.(*dns.SOARecord).Serial != toSOA.RecordData.(*dns.SOARecord).Serial {
		return fmt.Errorf(
			"%w: final SOA response at serial %d, not %d",
			ErrAxfr,
			soa.RecordData.(*dns.SOARecord).Serial,
			toSOA.RecordData.(*dns.SOARecord).Serial,
		)
	}

	// done!
	db.Enter(time.Time{}, false, []*dns.Record{soa})
	z.soa = soa
	z.db = db
	z.keys[""] = db
	delete(z.snapshots, "")

	return nil
}
