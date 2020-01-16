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
}

type rrmap map[uint32]*RRSet
type nset struct {
	rrmap
	readOnly bool // part of a snapshot; copy before updating
}
type names map[string]*nset

func typekey(rrtype dns.RRType, rrclass dns.RRClass) uint32 {
	return uint32(uint32(rrtype)<<16 | uint32(rrclass))
}

func (rr rrmap) get(rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, bool) {
	rrset, ok := rr[typekey(rrtype, rrclass)]
	return rrset, ok
}

func (rm rrmap) copy() rrmap {
	n := make(rrmap)
	for tkey, rrset := range rm {
		if rrset == nil || len(rrset.Records) == 0 {
			continue
		}
		n[tkey] = rrset.Copy()
	}
	return n
}

func (rr rrmap) set(rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) {
	tkey := typekey(rrtype, rrclass)
	if rrset == nil || len(rrset.Records) == 0 {
		delete(rr, tkey)
	} else {
		rr[tkey] = rrset
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
func (m *Memory) Clear() {
	for k, _ := range m.db {
		delete(m.db, k)
	}
}

func (m *Memory) copyKey(key string) {
	m.lk.Lock()
	ns, ok := m.db[key]
	if ok && ns.readOnly {
		m.db[key] = &nset{rrmap: ns.rrmap.copy()}
	}
	m.lk.Unlock()
}

// assumes lock held; safe with read lock
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

func (m *Memory) Lookup(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error) {
	key := name.Key()
	m.lk.RLock()

	ns, ok := m.db[key]
	if !ok || ns == nil || len(ns.rrmap) == 0 {
		m.lk.RUnlock()
		return nil, dns.NXDomain
	}
	rrset, _ := ns.get(rrtype, rrclass)

	m.lk.RUnlock()
	return rrset, nil
}

func (m *Memory) Enter(name dns.Name, rrtype dns.RRType, rrclass dns.RRClass, rrset *RRSet) error {
	key := name.Key()
	m.lk.Lock()

	ns, ok := m.db[key]
	if ok && ns.readOnly {
		ns = &nset{rrmap: ns.rrmap.copy()}
		m.db[key] = ns
	}
	if ns == nil {
		ns = &nset{rrmap: make(rrmap)}
		m.db[key] = ns
	}
	ns.set(rrtype, rrclass, rrset)

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
			for tkey, rs := range ns.rrmap {
				if rs == nil && len(rs.Records) == 0 {
					// nil or empty RRSet
					continue
				}
				var xr *RRSet
				if xs != nil {
					xr, _ = xs.rrmap[tkey]
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
		if err := delta(serial, from, to); err != nil {
			return err
		}
	}
	if err := delta(0, to, from); err != nil {
		return err
	}

	return nil
}
