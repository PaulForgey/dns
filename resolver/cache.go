package resolver

import (
	"time"

	"tessier-ashpool.net/dns"
)

type TypeKey uint32

func MakeTypeKeyFromRecord(record *dns.Record) TypeKey {
	return MakeTypeKey(record.Type(), record.Class())
}

func MakeTypeKey(rrtype dns.RRType, rrclass dns.RRClass) TypeKey {
	return TypeKey(rrtype)<<16 | TypeKey(rrclass)
}

func (t TypeKey) Types() (dns.RRType, dns.RRClass) {
	return dns.RRType(t >> 16), dns.RRClass(t & 0xffff)
}

func (t TypeKey) Match(rrtype dns.RRType, rrclass dns.RRClass) bool {
	mytype, myclass := t.Types()
	return mytype.Match(rrtype) && myclass.Match(rrclass)
}

type rrSet struct {
	records []*dns.Record
	entered time.Time
}

type rrMap map[TypeKey]*rrSet
type cacheMap map[string]rrMap

func (c cacheMap) get(name string, types TypeKey) *rrSet {
	if rrmap, ok := c[name]; ok {
		if rrset, ok := rrmap[types]; ok {
			return rrset
		}
	}
	return nil
}

// The Cache type holds records which may expire, adjusting TTL values when retrieved.
// Caches expect Zones to lock any concurrent access around the same instance.
type Cache struct {
	cache  cacheMap
	parent *Cache
}

// NewCache creates a new Cache instance
func NewCache(parent *Cache) *Cache {
	return &Cache{
		cache:  make(cacheMap),
		parent: parent,
	}
}

// Root returns the highest parent, suitable for caching records under an authoriative db. If there is no parent,
// the cache itself is returned.
func (c *Cache) Root() *Cache {
	for ; c.parent != nil; c = c.parent {
	}
	return c
}

// Enter adds or updates records with the timestamp in the at parameter. If at is the zero value, the records are permanent.
// Permanent records do not adjust their TTL values when retreived, and can only be overwritten other permanent records.
// Negative cache entries can exist by entering Records containing a nil RecordData value.
// TTL values of 0 will be entered having value 1.
// If merge is true (mdns), merge two sets of non-authoritative records, aging the existing TTL values. If merge is true
// and at is the zero value, Enter panics.
func (c *Cache) Enter(at time.Time, merge bool, records []*dns.Record) {
	authoritative := at.IsZero()
	if authoritative && merge {
		panic("attempt to merge authoritative records")
	}

	entries := make(cacheMap)
	for _, record := range records {
		nkey := record.RecordHeader.Name.Key()
		tkey := MakeTypeKeyFromRecord(record)

		crecord := &dns.Record{
			RecordHeader: dns.RecordHeader{
				Name:          record.Name,
				TTL:           record.RecordHeader.TTL,
				Type:          record.Type(),
				Class:         record.Class(),
				OriginalTTL:   record.RecordHeader.TTL,
				Authoritative: authoritative,
			},
			RecordData: record.RecordData,
		}

		if crecord.RecordHeader.TTL < time.Second {
			crecord.RecordHeader.TTL = time.Second
		}

		if rrmap, ok := entries[nkey]; ok {
			if rrset, ok := rrmap[tkey]; ok {
				rrset.records = append(rrset.records, crecord)
				rrset.entered = at

			} else {
				rrset := &rrSet{records: []*dns.Record{crecord}, entered: at}
				rrmap[tkey] = rrset
			}
		} else {
			rrmap := make(rrMap)
			rrset := &rrSet{records: []*dns.Record{crecord}, entered: at}
			rrmap[tkey] = rrset
			entries[nkey] = rrmap
		}
	}

	for nkey, rrmap := range entries {
		if crrmap, ok := c.cache[nkey]; ok {
			if authoritative {
				for tkey, rrset := range rrmap {
					crrmap[tkey] = rrset
				}
			} else {
				for tkey, rrset := range rrmap {
					if crrset, ok := crrmap[tkey]; ok {
						if crrset.entered.IsZero() {
							// do not overwrite permanent records with non permanent records
							continue
						}
						var crecords []*dns.Record
						expireSet(crrset, at, merge)
						for _, cr := range crrset.records {
							found := false
							for _, rr := range rrset.records {
								if cr.RecordData.Equal(rr.RecordData) {
									found = true
									break
								}
							}
							if !found {
								if merge {
									crecords = append(crecords, cr)
								} else {
									crecords = append(crecords, &dns.Record{
										RecordHeader: dns.RecordHeader{
											Name:        cr.RecordHeader.Name,
											TTL:         time.Second,
											Type:        cr.RecordHeader.Type,
											Class:       cr.RecordHeader.Class,
											OriginalTTL: cr.RecordHeader.OriginalTTL,
										},
										RecordData: cr.RecordData,
									})
								}
							}
						}
						rrset.records = append(rrset.records, crecords...)
					}

					crrmap[tkey] = rrset
				}
			}
		} else {
			c.cache[nkey] = rrmap
		}
	}
}

// Remove removes records:
// if RecordData is nil, all matching records of the type and class are removed.
// if RecordData is not nil, all matching records of the type, class, and data are removed.
// the record parameter may have a type and/or class of Any, which will remove all matches.
// Non permanent records are removed by having their TTL reduced to 1 and entered time set to now.
// If auth is true, SOA and NS records are protected if type is Any
// If no records were removed, Remove returns false
func (c *Cache) Remove(now time.Time, auth bool, record *dns.Record) bool {
	nkey := record.RecordHeader.Name.Key()
	rrmap, ok := c.cache[nkey]
	if !ok {
		return false // shortcut: stop here
	}
	if auth && (record.Type() == dns.NSType || record.Type() == dns.SOAType) {
		return false // shortcut: attempt to snipe auth record
	}

	rrtype, rrclass := record.Type(), record.Class()
	tkey := MakeTypeKey(rrtype, rrclass)
	rrsets := make(rrMap)
	data := record.RecordData

	if rrtype != dns.AnyType && rrclass != dns.AnyClass {
		if rrset, ok := rrmap[tkey]; ok {
			rrsets[tkey] = rrset
		}
	} else {
		data = nil // ignore RecordData
		for tkey, rrset := range rrmap {
			if tkey.Match(rrtype, rrclass) {
				if auth {
					t, _ := tkey.Types()
					if t == dns.SOAType || t == dns.NSType {
						continue
					}
				}
				rrsets[tkey] = rrset
			}
		}
	}

	updated := false

	// rrsets contains candidate type+class[rrset] to be removed
	for tkey, rrset := range rrsets {
		if rrset.entered.IsZero() {
			// authoritative records

			var records []*dns.Record // surviving records
			if data != nil {
				for _, rr := range rrset.records {
					if !rr.RecordData.Equal(data) {
						records = append(records, rr)
					} else {
						updated = true
					}
				}
			}
			if len(records) == 0 {
				updated = true
				delete(rrmap, tkey)
			} else {
				rrset.records = records
			}
		} else {
			// cached or mdns shared records

			var records []*dns.Record // records to reset
			expireSet(rrset, now, true)
			rrset.entered = now
			if data == nil {
				records = rrset.records
			} else {
				for _, rr := range rrset.records {
					if rr.RecordData.Equal(data) {
						records = append(records, rr)
					}
				}
			}
			for _, rr := range records {
				updated = true
				rr.RecordHeader.TTL = time.Second
			}
		}
	}

	return updated
}

// used with Enter while merging records or Get, expire records from the cache and if merging, backdate their TTLs to
// adjust for rrset.Entered to eventually be now
func expireSet(rrset *rrSet, now time.Time, adjust bool) {
	var newRecords []*dns.Record

	if adjust && rrset.entered.IsZero() {
		// this operation only makes sense when merging records (mdns), which means we cached them
		// mdns servers, like any other server, have their authoritative zone data in another cache layer above us
		panic("attempt to adjust TTL of authoritative cache entries")
	}

	for _, rr := range rrset.records {
		if rrset.entered.IsZero() || now.Before(rrset.entered.Add(rr.RecordHeader.TTL)) {
			if adjust {
				rr.RecordHeader.TTL -= now.Sub(rrset.entered)
			}
			newRecords = append(newRecords, rr)
		}
	}
	if len(newRecords) > 1 {
		r0 := newRecords[0]
		copy(newRecords, newRecords[1:])
		newRecords[len(newRecords)-1] = r0
	}
	rrset.records = newRecords
}

// Get retrieves records from the cache matching the name, rrtype and rrclass.
// now can not be the zero value.
// dns.AnyType and dns.AnyClass will wildcard match.
// Non permanent records will have their TTL values adjusted.
// Expired records will be removed from the cache and not returned.
// If there are no entries for the name regardless of type, dns.NXDomain is returned
func (c *Cache) Get(now time.Time, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) ([]*dns.Record, error) {
	var records []*dns.Record
	var err error

	if now.IsZero() {
		panic("now cannot be zero")
	}

	nkey := name.Key()

	rrmap, ok := c.cache[nkey]
	if ok && len(rrmap) > 0 {
		var tkeys []TypeKey
		if rrtype == dns.AnyType || rrclass == dns.AnyClass {
			for tkey := range rrmap {
				t, _ := tkey.Types()
				if t == dns.CNAMEType || tkey.Match(rrtype, rrclass) {
					tkeys = append(tkeys, tkey)
				}
			}
		} else {
			if rrtype != dns.CNAMEType {
				tkeys = []TypeKey{
					MakeTypeKey(rrtype, rrclass),
					MakeTypeKey(dns.CNAMEType, rrclass),
				}
			} else {
				tkeys = []TypeKey{
					MakeTypeKey(rrtype, rrclass),
				}
			}
		}

		for _, tkey := range tkeys {
			rrset, ok := rrmap[tkey]

			if ok {
				authoritative := rrset.entered.IsZero()
				expireSet(rrset, now, false)
				for _, rr := range rrset.records {
					var backdate time.Duration

					if !authoritative {
						backdate = now.Sub(rrset.entered)
					}
					// expireSet guarantees the following will not produce 0 TTL records
					if rr.RecordHeader.TTL <= backdate {
						panic("expireSet() left TTL <= 0")
					}
					record := &dns.Record{
						RecordHeader: dns.RecordHeader{
							Name:          name,
							TTL:           rr.RecordHeader.TTL - backdate,
							OriginalTTL:   rr.RecordHeader.OriginalTTL,
							Authoritative: authoritative,
							Type:          rr.RecordHeader.Type,
							Class:         rr.RecordHeader.Class,
						},
						RecordData: rr.RecordData,
					}
					records = append(records, record)
				}
			}
		}
	} else {
		ok = false
		err = dns.NXDomain
	}

	if !ok && c.parent != nil {
		return c.parent.Get(now, name, rrtype, rrclass)
	}

	return records, err
}

// Clone peels off a copy of the zone for checkpointing, zone transfers, etc.
// If exclude is not nil, records present will be excluded from the result.
// The copied records are only authoritative ones. The RecordData fields of the records are referenced, not copied.
// The set of returned records is also from the point of view of the cache shadowing its parent. The cloned cache
// thus has no parent.
// SOA records are omitted.
func (c *Cache) Clone(exclude *Cache) *Cache {
	copyIn := func(to, from cacheMap) {
		for nkey, frrmap := range from {
			trrmap, ok := to[nkey]
			if !ok {
				trrmap = make(rrMap)
				to[nkey] = trrmap
			}
			for rrkey, frrset := range frrmap {
				ftype, _ := rrkey.Types()
				if ftype == dns.SOAType || !frrset.entered.IsZero() {
					continue
				}
				trrset, ok := trrmap[rrkey]
				if ok {
					continue
				}

				trrset = &rrSet{}
				var xrrset *rrSet

				if exclude != nil {
					x := exclude
					for xrrset == nil && x != nil {
						xrrset = x.cache.get(nkey, rrkey)
						x = x.parent
					}
				}

				if xrrset != nil {
					for _, f := range frrset.records {
						found := false
						for _, x := range xrrset.records {
							if f.RecordData.Equal(x.RecordData) {
								found = true
								break
							}
						}
						if !found {
							trrset.records = append(trrset.records, f)
						}
					}
				} else {
					trrset.records = make([]*dns.Record, len(frrset.records))
					copy(trrset.records, frrset.records)
				}

				trrmap[rrkey] = trrset
			}
		}
	}

	dup := NewCache(nil)
	copyIn(dup.cache, c.cache)
	for p := c.parent; p != nil; p = p.parent {
		copyIn(dup.cache, p.cache)
	}

	return dup
}

// Patch removes and adds records from remove and add if not nil
func (c *Cache) Patch(remove, add *Cache) {
	if remove != nil {
		for nkey, rrmap := range c.cache {
			for tkey, rrset := range rrmap {
				if xrrset := remove.cache.get(nkey, tkey); xrrset != nil {
					records := []*dns.Record{}
					for _, r := range rrset.records {
						found := false
						for _, x := range xrrset.records {
							if r.RecordData.Equal(x.RecordData) {
								found = true
								break
							}
						}
						if !found {
							records = append(records, r)
						}
					}
					rrset.records = records
				}
			}
		}
	}
	if add != nil {
		for ankey, arrmap := range add.cache {
			rrmap, ok := c.cache[ankey]
			if !ok {
				rrmap = make(rrMap)
				c.cache[ankey] = rrmap
			}
			for atkey, arrset := range arrmap {
				rrset, ok := rrmap[atkey]
				if !ok {
					rrmap[atkey] = arrset
				} else {
					rrset.records = append(rrset.records, arrset.records...)
				}
			}
		}
	}
}

// Enumerate calls f for every record, excluding SOA
func (c *Cache) Enumerate(rrclass dns.RRClass, f func(r *dns.Record) error) error {
	for _, rrmap := range c.cache {
		for tkey, rrset := range rrmap {
			t, c := tkey.Types()
			if t == dns.SOAType || !rrclass.Match(c) {
				continue
			}
			for _, r := range rrset.records {
				if err := f(r); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Clear clears all records.
// If auth is true, only authoritative records are removed
func (c *Cache) Clear(auth bool) {
	for nkey, rrmap := range c.cache {
		if auth {
			for tkey, rrset := range rrmap {
				if rrset.entered.IsZero() {
					delete(rrmap, tkey)
				}
			}
		} else {
			delete(c.cache, nkey)
		}
	}
}
