package nsdb

import (
	"sync"

	"tessier-ashpool.net/dns"
)

const maxSnapshots = 5

// the Memory type is an in memory implementation of Db, suitable for caching or zones backed by textual files.
type Memory struct {
	lk        *sync.RWMutex
	snapshots map[uint32]names // COW'd records by snapshot
	snaplist  []uint32         // snapshots in creation order, oldest first
	db        names            // actual database
	update    names            // update transaction
}

type tkey uint32
type rrmap map[tkey]*RRSet
type nset struct {
	rrmap
	readOnly bool // part of a snapshot; copy before updating
}
type names map[string]*nset

func typekey(rrtype dns.RRType, rrclass dns.RRClass) tkey {
	return tkey(uint32(rrtype)<<16 | uint32(rrclass))
}

func (t tkey) match(exact bool, rrtype dns.RRType, rrclass dns.RRClass) bool {
	mytype := dns.RRType(uint32(t) >> 16)
	myclass := dns.RRClass(t & 0xffff)
	if rrtype.Asks(mytype) && rrclass.Asks(myclass) {
		// if exact, do not hit CNAMEs if we didn't ask for them
		return !(exact && (rrtype != dns.AnyType && rrtype != mytype))
	}
	return false
}

func (rr rrmap) get(rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, bool) {
	rrset, ok := rr[typekey(rrtype, rrclass)]
	return rrset, ok
}

func (rm rrmap) copy() rrmap {
	n := make(rrmap)
	for t, rrset := range rm {
		if rrset == nil {
			continue
		}
		n[t] = rrset.Copy()
	}
	return n
}

func (rr rrmap) set(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) {
	t := typekey(rrtype, rrclass)
	if rrset == nil {
		delete(rr, t)
	} else {
		rr[t] = rrset
	}
}

// NewMemory creates an empty Memory instance
func NewMemory() *Memory {
	return &Memory{
		lk:        &sync.RWMutex{},
		snapshots: make(map[uint32]names),
		db:        make(names),
	}
}

// Clear removes all records (snapshots are unaffected)
func (m *Memory) Clear() error {
	m.lk.Lock()
	defer m.lk.Unlock()

	var db names
	if m.update != nil {
		db = m.update
	} else {
		db = m.db
	}

	for k, _ := range db {
		delete(db, k)
	}
	return nil
}

// assumes lock held; safe with read lock.
// returns a COW'd shallow copy of the database
func (m *Memory) snapshot_locked() names {
	snapshot := make(names)
	for key, ns := range m.db {
		ns.readOnly = true // safe under read lock; only consumed under write lock
		snapshot[key] = ns
	}
	return snapshot
}

func (m *Memory) Snapshot(snapshot uint32) error {
	m.lk.Lock()
	defer m.lk.Unlock()
	if _, ok := m.snapshots[snapshot]; ok {
		return nil // already snapshotted here
	}
	if len(m.snaplist) == maxSnapshots {
		delete(m.snapshots, m.snaplist[0])
		copy(m.snaplist, m.snaplist[1:])
		m.snaplist[len(m.snaplist)-1] = snapshot
	} else {
		m.snaplist = append(m.snaplist, snapshot)
	}
	m.snapshots[snapshot] = m.snapshot_locked()
	return nil
}

func (m *Memory) BeginUpdate() error {
	m.lk.Lock()
	defer m.lk.Unlock()

	if m.update != nil {
		return ErrAlreadyUpdating
	}
	m.update = m.snapshot_locked()
	return nil
}

func (m *Memory) EndUpdate(abort bool) error {
	m.lk.Lock()
	defer m.lk.Unlock()

	if m.update == nil {
		return ErrNotUpdating
	}
	if !abort {
		m.db = m.update
	}
	m.update = nil
	return nil
}

func (m *Memory) Lookup(exact bool, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error) {
	key := name.Key()
	m.lk.RLock()

	var db names
	if m.update != nil {
		db = m.update
	} else {
		db = m.db
	}

	ns, ok := db[key]
	if !ok || ns == nil || len(ns.rrmap) == 0 {
		m.lk.RUnlock()
		return nil, dns.NXDomain
	}

	var rrset *RRSet

	if !exact && rrclass != dns.AnyClass {
		rrset, _ = ns.get(dns.CNAMEType, rrclass)
		if rrset != nil {
			m.lk.RUnlock()
			return rrset, nil
		}
	}

	rotate := false

	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		rrset = &RRSet{}
		for t, rs := range ns.rrmap {
			if t.match(exact, rrtype, rrclass) {
				rrset.Records = append(rrset.Records, rs.Records...)
			}
		}
	} else {
		rrset, _ = ns.get(rrtype, rrclass)
		if rrset != nil {
			rotate = len(rrset.Records) > 1
		}
	}

	m.lk.RUnlock()
	if rotate {
		m.lk.Lock()
		rrset.Rotate()
		m.lk.Unlock()
	}

	return rrset, nil
}

func (m *Memory) Enter(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error {
	if rrset != nil && len(rrset.Records) == 0 {
		rrset = nil
	}
	if rrset != nil && (rrtype == dns.AnyType || rrclass == dns.AnyClass) {
		return ErrInvalidRRSet
	}

	key := name.Key()
	m.lk.Lock()

	var db names
	if m.update != nil {
		db = m.update
	} else {
		db = m.db
	}

	ns, ok := db[key]
	if ok && ns.readOnly {
		ns = &nset{rrmap: ns.rrmap.copy()}
		db[key] = ns
	}

	if ns == nil {
		ns = &nset{rrmap: make(rrmap)}
		db[key] = ns
	}

	if rrtype == dns.AnyType || rrclass == dns.AnyClass {
		for t, _ := range ns.rrmap {
			if t.match(true, rrtype, rrclass) {
				delete(ns.rrmap, t)
			}
		}
	} else {
		ns.set(rrtype, rrclass, rrset)
	}

	m.lk.Unlock()
	return nil
}

func (m *Memory) Enumerate(serial uint32, f func(uint32, []*dns.Record) error) error {
	var from, to names

	m.lk.RLock()
	if serial != 0 {
		from, _ = m.snapshots[serial]
	}
	to = m.snapshot_locked()
	m.lk.RUnlock()

	delta := func(serial uint32, snapshot, exclude names) error {
		for key, ns := range snapshot {
			var xs *nset
			if exclude != nil {
				xs, _ = exclude[key]
			}
			if xs == ns {
				// both sides of the delta are equal for the entire name
				continue
			}
			for t, rs := range ns.rrmap {
				if rs == nil {
					// empty RRSet
					continue
				}
				var xr *RRSet
				if xs != nil {
					xr, _ = xs.rrmap[t]
				}
				records := rs.Records
				if xr != nil {
					records = xr.Exclude(records)
				}
				if len(records) > 0 {
					if err := f(serial, records); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}

	if from != nil {
		// send an empty header so the client knows this is a delta
		if err := f(serial, nil); err != nil {
			return err
		}
		if err := delta(serial, from, to); err != nil {
			return err
		}
	}
	if err := delta(0, to, from); err != nil {
		return err
	}

	return nil
}
