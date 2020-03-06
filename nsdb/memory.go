package nsdb

import (
	"sync"
	"sync/atomic"

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
	stats     *MemoryStats
}

// the MemoryStats type is the actual type returned by the Stats interface method
type MemoryStats struct {
	Entries    int32
	Snapshots  int32
	NXDomain   int32
	Retrievals int32
	Updates    int32
	Deletes    int32
}

type names map[string]*RRMap

// NewMemory creates an empty Memory instance
func NewMemory() *Memory {
	return &Memory{
		lk:        &sync.RWMutex{},
		snapshots: make(map[uint32]names),
		db:        make(names),
		stats:     &MemoryStats{},
	}
}

func (m *Memory) Stats() interface{} {
	return m.stats
}

func (m *Memory) Save() error {
	return nil
}

func (m *Memory) Flags() DbFlags {
	return DbLiveUpdateFlag
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
	atomic.StoreInt32(&m.stats.Entries, 0)
	return nil
}

// assumes lock held; safe with read lock.
// returns a COW'd shallow copy of the database
func (m *Memory) snapshot_locked() names {
	snapshot := make(names)
	for key, ns := range m.db {
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
	atomic.StoreInt32(&m.stats.Snapshots, int32(len(m.snaplist)))
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

func (m *Memory) Lookup(name dns.Name) (*RRMap, error) {
	key := name.Key()
	m.lk.RLock()
	defer m.lk.RUnlock()

	var db names
	if m.update != nil {
		db = m.update
	} else {
		db = m.db
	}

	ns, ok := db[key]

	if !ok || len(ns.Map) == 0 {
		atomic.AddInt32(&m.stats.NXDomain, 1)
		return ns, dns.NXDomain
	}
	atomic.AddInt32(&m.stats.Retrievals, 1)
	return ns, nil
}

func (m *Memory) Enter(name dns.Name, value *RRMap) error {
	key := name.Key()
	m.lk.Lock()
	defer m.lk.Unlock()

	var db names
	if m.update != nil {
		db = m.update
	} else {
		db = m.db
	}

	if value == nil || (len(value.Map) == 0 && value.Negative.IsZero()) {
		atomic.AddInt32(&m.stats.Deletes, 1)
		delete(db, key)
	} else {
		atomic.AddInt32(&m.stats.Updates, 1)
		db[key] = value
	}
	atomic.StoreInt32(&m.stats.Entries, int32(len(db)))

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
			var xs *RRMap
			if exclude != nil {
				xs, _ = exclude[key]
			}
			for t, rs := range ns.Map {
				if rs == nil {
					// empty RRSet
					continue
				}
				var xr *RRSet
				if xs != nil {
					xr, _ = xs.Map[t]
				}
				records := rs.Records
				if xr != nil {
					records = dns.Subtract(records, xr.Records)
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
