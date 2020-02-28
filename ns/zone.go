package ns

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
	"tessier-ashpool.net/dns/resolver"
)

var ErrIxfr = errors.New("SOA does not match for IXFR")
var ErrAxfr = errors.New("Mismatched or unexpected SOA values")
var ErrNoKey = errors.New("zone has no database with this key")
var ErrXferInProgress = errors.New("zone is already transferring")

// the UpdateLog interface hooks zone updates.
type UpdateLog interface {
	// if Update returns an error, the update does not occur and the error is returned to the caller of the zone's update
	Update(key string, update []*dns.Record) error
}

// the Zones type holds all the zones we know of
type Zones struct {
	sync.RWMutex
	zones map[string]*Zone
}

// the Zone type is a specialization of the resolver Zone with additional information needed by the server
type Zone struct {
	*resolver.Zone
	UpdateLog UpdateLog
	Primary   string // address of primary server to forward updates

	// access control (not applicable to mDNS)
	AllowQuery    Access
	AllowUpdate   Access
	AllowTransfer Access
	AllowNotify   Access

	// server interaction
	online bool
	r      chan struct{} // reload
	u      chan struct{} // update

	// update hazard
	updateWait   *sync.WaitGroup
	updateLock   *sync.Mutex
	updateCond   *sync.Cond
	blockUpdates bool

	// authoritative database
	xferlock int32
	updated  bool
	soa      *dns.Record
	keys     map[string]nsdb.Db
	db       nsdb.Db

	// mDNS persistent queries
	queries map[chan<- struct{}]mdnsQuery
}

type mdnsQuery struct {
	iface string
	q     dns.Question
}

func (z *Zone) init() {
	z.r = make(chan struct{}, 1)
	z.u = make(chan struct{}, 1)
	z.updateWait = &sync.WaitGroup{}
	z.updateLock = &sync.Mutex{}
	z.updateCond = sync.NewCond(z.updateLock)
	z.queries = make(map[chan<- struct{}]mdnsQuery)

	z.keys = make(map[string]nsdb.Db)
}

// NewZone creates a new, empty zone for use by the server
func NewZone(name dns.Name, hint bool) *Zone {
	z := &Zone{
		Zone: resolver.NewZone(name, hint),
	}
	z.init()
	return z
}

// NewCacheZone creates a new zone backed by an existing resolver cache
func NewCacheZone(cache *resolver.Zone) *Zone {
	z := &Zone{
		Zone: cache,
	}
	z.init()
	return z
}

// PersistentQuery installs a notification on the zone for q. If q is nil, the channel is removed from notifications.
// The channel is written non blocking. A zone reloading or transferring will not trigger this mechanism.
func (z *Zone) PersistentQuery(c chan<- struct{}, iface string, q dns.Question) {
	z.Lock()
	if q == nil {
		delete(z.queries, c)
	} else {
		z.queries[c] = mdnsQuery{iface, q}
	}
	z.Unlock()
}

// Attach associates a database with a zone or a zone's interface specific records.
func (z *Zone) Attach(key string, db nsdb.Db) error {
	z.Lock()
	defer z.Unlock()

	if key == "" {
		rrset, err := nsdb.Lookup(db, true, z.Name(), dns.SOAType, dns.AnyClass)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return err
		}
		if rrset != nil && len(rrset.Records) > 0 {
			z.soa = rrset.Records[0]
		}
		z.db = db
	}
	z.keys[key] = db
	return nil
}

// Db returns the database associated with a key, if any
func (z *Zone) Db(key string) nsdb.Db {
	z.RLock()
	db, _ := z.keys[key]
	z.RUnlock()
	return db
}

// Save syncs the db behind the given key to stable storage, if applicable
func (z *Zone) Save(key string) error {
	z.RLock()
	soa := z.soa
	if soa == nil {
		z.RUnlock()
		return ErrNoSOA
	}
	for z.updated {
		// insure we are left holding a read lock with up to date SOA
		z.RUnlock()
		z.Lock()
		soa = z.soa_locked()
		z.Unlock()
		z.RLock()
	}
	db, ok := z.keys[key]
	z.RUnlock()
	if !ok {
		return ErrNoKey // this is a shallow operation, so wrong key is an error
	}

	if (db.Flags() & nsdb.DbLiveUpdateFlag) != 0 {
		return nil // nothing to do
	}

	return db.Save()
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
		nsdb.Enter(z.db, r.Name(), r.Type(), r.Class(), update)
		if z.UpdateLog != nil {
			z.UpdateLog.Update("", update.Records)
		}
	}

	return r
}

// Retrieve SOA data.
func (z *Zone) SOA() *dns.Record {
	var r *dns.Record

	z.RLock()
	r = z.soa
	if r != nil && z.updated {
		z.RUnlock()
		z.Lock()
		r = z.soa_locked()
		z.Unlock()
	} else {
		z.RUnlock()
	}
	return r
}

// Class returns the class for the zone.
func (z *Zone) Class() dns.RRClass {
	z.RLock()
	rrclass := dns.InvalidClass
	if z.soa != nil {
		rrclass = z.soa.Class()
	}
	z.RUnlock()
	return rrclass
}

// MLookup is like resolver.Zone.MLookup, but potentially combine our authority with the cache.
// if authoritative is true, return only our authority.
func (z *Zone) MLookup(
	key string,
	where resolver.Scope,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (a []*dns.Record, exclusive bool, err error) {
	z.RLock()
	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}
	db2 := z.db
	z.RUnlock()

	// check our authority first, then the underlying cache
	if (where & resolver.InAuth) != 0 {
		for db != nil {
			var rm *nsdb.RRMap
			rm, err = z.lookup(db, name)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return
			}

			if rm != nil {
				exclusive = exclusive || rm.Exclusive
				rrset := rm.Lookup(true, rrtype, rrclass)
				if rrset != nil {
					a = dns.Merge(a, rrset.Records)
				}
			}

			if db != db2 && db2 != nil {
				db = db2
			} else {
				db = nil
			}
		}
	}

	if (where&resolver.InCache) != 0 && !exclusive {
		var a2 []*dns.Record
		a2, exclusive, err = z.Zone.MLookup(key, where, name, rrtype, rrclass)
		if err != nil {
			return
		}
		a = dns.Merge(a2, a)
	}

	if exclusive && rrtype != dns.NSECType {
		var a2 []*dns.Record
		a2, _, err = z.MLookup("", where, name, dns.NSECType, rrclass)
		a = dns.Merge(a, a2)
	}

	err = nil
	return
}

// Remove returns all the records for a given name in all its interface scopes.
// The underlying cache is also removed, however its records are not returned as they are not authoritative and are not
// likely to be present under normal circumstances.
func (z *Zone) Remove(name dns.Name) (resolver.IfaceRRSets, error) {
	abort := true

	z.Lock()
	defer func() {
		if abort {
			for _, db := range z.keys {
				db.EndUpdate(true)
			}
			z.Unlock()
		}
	}()

	for _, db := range z.keys {
		if err := db.BeginUpdate(); err != nil {
			return nil, err
		}
	}

	rrsets := make(resolver.IfaceRRSets)
	for iface, db := range z.keys {
		rrmap, err := db.Lookup(name)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, err
		}
		if rrmap != nil {
			for _, rrset := range rrmap.Map {
				rrsets[iface] = append(rrsets[iface], rrset.Records...)
			}
		}
		if err := db.Enter(name, nil); err != nil {
			return nil, err
		}
	}

	abort = false
	for _, db := range z.keys {
		db.EndUpdate(false)
	}
	z.Unlock()

	z.Zone.Remove(name)
	return rrsets, nil
}

func (z *Zone) Lookup(
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	// check the cache
	a, ns, err := z.Zone.Lookup(key, name, rrtype, rrclass)
	if len(a) > 0 || (err != nil && (!errors.Is(err, dns.NXDomain) || errors.Is(err, nsdb.ErrNegativeAnswer))) {
		return a, ns, err
	}

	// database
	z.RLock()
	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}
	z.RUnlock()

	if db == nil {
		return a, ns, err
	}

	a, ns2, err := z.LookupDb(db, false, name, rrtype, rrclass)
	ns = append(ns, ns2...)
	if db == z.db || len(a) > 0 || (err != nil && !errors.Is(err, dns.NXDomain)) {
		if len(ns) > 0 && err != nil {
			if errors.Is(err, dns.NXDomain) {
				err = nil
			} else {
				ns = nil
			}
		}
		return a, ns, err
	}

	// base database (unkeyed)
	a, ns2, err = z.LookupDb(z.db, false, name, rrtype, rrclass)
	ns = append(ns, ns2...)
	if len(ns) > 0 && err != nil {
		if errors.Is(err, dns.NXDomain) {
			err = nil
		} else {
			ns = nil
		}
	}
	return a, ns, err
}

// Dump returns all records for a zone, optionally since a given soa.
// If serial is 0 or the zone does not have history for serial, a full result set is returned, otherwise an incremental result.
// The current serial will be snapshotted for future history if it was not already.
func (z *Zone) Dump(serial uint32, rrclass dns.RRClass, next func(*dns.Record) error) (uint32, error) {
	var toSerial uint32

	z.Lock()

	if z.db == nil {
		z.Unlock()
		return 0, ErrNoKey
	}
	soa := z.soa_locked()
	if soa == nil {
		z.Unlock()
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

	z.Unlock()

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
			if r.Type() == dns.SOAType || !rrclass.Asks(r.Class()) {
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
func (z *Zone) Xfer(ixfr bool, nextRecord func() (*dns.Record, error)) error {
	var db nsdb.Db
	abort := true

	z.RLock()

	defer func() {
		if db != nil {
			db.EndUpdate(abort)
		}
		atomic.AddInt32(&z.xferlock, -1)
		z.RUnlock()
	}()

	if atomic.AddInt32(&z.xferlock, 1) > 1 {
		return ErrXferInProgress
	}

	if z.db == nil {
		return ErrNoKey
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

	if !ixfr {
		if err := db.Clear(); err != nil {
			return err
		}
	}

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

					if _, err := nsdb.Patch(z.db, time.Time{}, del, add); err != nil {
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

	if err := nsdb.Enter(z.db, soa.Name(), dns.SOAType, soa.Class(), &nsdb.RRSet{Records: []*dns.Record{soa}}); err != nil {
		return err
	}

	// done!
	abort = false
	z.soa = soa // XXX potential data race (read lock)
	return nil
}

// Update processes updates to a zone
func (z *Zone) Update(key string, prereq, update []*dns.Record) (bool, error) {
	var db nsdb.Db
	var ok bool

	abort := true

	z.Lock()
	defer func() {
		z.Unlock()
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
	if db == nil {
		return false, ErrNoKey
	}
	if err := db.BeginUpdate(); err != nil {
		db = nil
		return false, err
	}

	// process the prereq
	for _, r := range prereq {
		if !r.Name().HasSuffix(z.Name()) {
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

		rrmap, err := z.lookup(db, r.Name())
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return false, err
		}
		var rrset *nsdb.RRSet
		if rrmap != nil {
			rrset = rrmap.Lookup(false, rrtype, rrclass)
		}
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
		if !r.Name().HasSuffix(z.Name()) {
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
		auth := name.Equal(z.Name())

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
				time.Time{},
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

			rrset, err := nsdb.Lookup(db, false, name, rrtype, rrclass)
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
			if err := nsdb.Enter(db, name, rrtype, rrclass, update); err != nil {
				return false, err
			}
			updated = true
		}
	}

	if err := z.postupdate_locked(updated, key, update); err != nil {
		return false, err
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

func (z *Zone) postupdate_locked(updated bool, key string, update []*dns.Record) error {
	if updated {
		// only write update log if there is a net change
		if z.UpdateLog != nil {
			if err := z.UpdateLog.Update(key, update); err != nil {
				return err
			}
		}
	}
	// regardless of net change, this counts as update activity on zone (e.g. freshened ttl)
	for c, mq := range z.queries {
		for _, r := range update {
			if !(key == "" || mq.iface == "" || key == mq.iface) {
				continue
			}
			q := mq.q
			if q.Name().Equal(r.Name()) &&
				q.Class().Asks(r.Class()) &&
				(q.Type().Asks(r.Type()) || r.Type() == dns.NSECType) {
				select {
				case c <- struct{}{}:
				default: // do not block
				}
				break // hit notification only once
			}
		}
	}

	return nil
}

func (z *Zone) lookup(db nsdb.Db, name dns.Name) (*nsdb.RRMap, error) {
	rrmap, err := db.Lookup(name)
	if err != nil && !errors.Is(err, dns.NXDomain) {
		return nil, err
	}
	if db != z.db && z.db != nil {
		rrmap2, err := z.db.Lookup(name)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			return nil, err
		}
		if rrmap2 != nil {
			if rrmap == nil {
				rrmap = rrmap2
			} else {
				rrmap = rrmap.Copy()
				rrmap.Merge(rrmap2)
			}
		}
	}
	return rrmap, nil
}

// Enter enters recods into the zone, such as from mDNS or other external means. If there is no existing backing db
// for key, a Memory type db is created for it.
// If now is non-zero, the updates are passed to the cache layer and are considered non authoritative unless there are
// conflicting authoriative records, in which case the conflicting records are not added but are returned
func (z *Zone) Enter(now time.Time, key string, records []*dns.Record) ([]*dns.Record, error) {
	var db nsdb.Db
	abort := true

	z.Lock()
	defer func() {
		if db != nil {
			z.Unlock()
			if now.IsZero() {
				db.EndUpdate(abort)
			}
		}
	}()

	db, _ = z.keys[key]
	if db == nil {
		db = nsdb.NewMemory()
		z.keys[key] = db
		if key == "" {
			z.db = db
		}
	}
	if now.IsZero() {
		var remove, add []*dns.Record

		if err := db.BeginUpdate(); err != nil {
			return nil, err
		}

		for _, r := range records {
			if r.D != nil {
				add = append(add, r)
			} else {
				remove = append(remove, r)
			}
		}

		updated, err := nsdb.Patch(db, time.Time{}, remove, add)
		if err != nil {
			return nil, err
		}

		if err := z.postupdate_locked(updated, key, records); err != nil {
			return nil, err
		}

		abort = false
		return nil, nil
	} else {
		var add, conflict []*dns.Record

		err := dns.RecordSets(records, func(name dns.Name, records []*dns.Record) error {
			rrmap, err := z.lookup(db, name)
			if err != nil && !errors.Is(err, dns.NXDomain) {
				return err
			}
			if rrmap == nil || !rrmap.Exclusive {
				add = append(add, records...)
				return nil
			}
			for _, rr := range records {
				rs := rrmap.Lookup(true, rr.Type(), rr.Class())
				if dns.Find(rs.Records, rr) < 0 {
					conflict = append(conflict, rr)
				} else {
					add = append(add, rr)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}

		z.postupdate_locked(false, key, add)

		db = nil
		z.Unlock()

		_, err = z.Zone.Enter(now, key, add)
		return conflict, err
	}
}

// Reload signals the zone to reload by making the channel in ReloadC() readable
func (z *Zone) Reload() {
	select {
	case z.r <- struct{}{}:
	default: // do not block
	}
}

// Notify signals the zone to send notifications of an update by making the channel in UpdateC() reable
func (z *Zone) Notify() {
	select {
	case z.u <- struct{}{}:
	default: // do not block
	}
}

// ReloadC returns a channel which is readable when the zone requests to be reloaded
func (z *Zone) ReloadC() <-chan struct{} {
	return z.r
}

// NotifyC returns a channel which is readable when the zone requests to send notifications
func (z *Zone) NotifyC() <-chan struct{} {
	return z.u
}

// HoldUpdates blocks updates from occuring until ReleaseUpdates is called
func (z *Zone) HoldUpdates() {
	z.updateLock.Lock()
	if z.blockUpdates {
		panic("HoldUpdates on held updates")
	}
	z.blockUpdates = true
	z.updateLock.Unlock()
	z.updateWait.Wait()
}

func (z *Zone) ReleaseUpdates() {
	z.updateLock.Lock()
	if !z.blockUpdates {
		panic("ReleaseUpdates on released updated")
	}
	z.blockUpdates = false
	z.updateCond.Broadcast()
	z.updateLock.Unlock()
}

func (z *Zone) EnterUpdateFence() {
	z.updateLock.Lock()
	for z.blockUpdates {
		z.updateCond.Wait()
	}
	z.updateWait.Add(1)
	z.updateLock.Unlock()
}

func (z *Zone) LeaveUpdateFence() {
	z.updateWait.Done()
}

// NewZones creates an empty Zones
func NewZones() *Zones {
	return &Zones{
		zones: make(map[string]*Zone),
	}
}

// Insert adds or overwrites a zone
func (zs *Zones) Insert(z *Zone, online bool) {
	zs.Lock()
	z.online = online
	zs.zones[z.Name().Key()] = z
	zs.Unlock()
}

// Remove removes a zone
func (zs *Zones) Remove(z *Zone) {
	zs.Lock()
	z.online = false
	delete(zs.zones, z.Name().Key())
	zs.Unlock()
}

// Offline marks a zone offline
func (zs *Zones) Offline(z *Zone) {
	zs.Lock()
	z.online = false
	zs.Unlock()
}

// Finds a zone by name having the closest common suffix.
// Find can return nil if the root zone is not present.
func (zs *Zones) Find(n dns.Name) resolver.ZoneAuthority {
	var z *Zone
	var ok bool

	zs.RLock()

	for {
		z, ok = zs.zones[n.Key()]
		if ok || len(n) == 0 {
			break
		}
		n = n.Suffix()
	}

	if z != nil && !z.online {
		z = nil
	}

	zs.RUnlock()
	if z == nil {
		return nil
	}
	return z
}

// Zone returns the zone by exact match, online or not
func (zs *Zones) Zone(n dns.Name) *Zone {
	zs.RLock()
	z, _ := zs.zones[n.Key()]
	zs.RUnlock()
	return z
}

// Additional fills in the additional section if it can from either cache or authority
func (zs *Zones) Additional(mdns bool, msg *dns.Message) {
	records := make([]*dns.Record, 0, len(msg.Authority)+len(msg.Answers)+len(msg.Additional))
	records = append(records, msg.Authority...)
	records = append(records, msg.Answers...)
	records = append(records, msg.Additional...)

	for i := 0; i < len(records); i++ {
		rec := records[i]

		var name dns.Name
		var rrtype dns.RRType

		switch rec.Type() {
		case dns.AType:
			name = rec.Name()
			rrtype = dns.AAAAType

		case dns.AAAAType:
			name = rec.Name()
			rrtype = dns.AType

		default:
			if n, ok := rec.D.(dns.NameRecordType); ok && !n.RName().Equal(rec.Name()) {
				name = n.RName()
				rrtype = dns.AnyType
			}
		}

		if name == nil {
			continue
		}

		// make sure we haven't already put it in
		found := false
		for _, a := range records {
			if a.Name().Equal(name) && rrtype.Asks(a.Type()) {
				found = true
				break
			}
		}
		if found {
			continue
		}

		zone := zs.Find(name)
		if zone == nil {
			continue
		}

		// find it from cache
		var answers []*dns.Record
		if mdns {
			answers, _, _ = zone.MLookup(msg.Iface, resolver.InAuth, name, rrtype, rec.Class())
		} else {
			answers, _, _ = zone.Lookup(msg.Iface, name, rrtype, rec.Class())
		}
		for _, a := range answers {
			if a.D == nil {
				continue
			}
			switch a.Type() {
			case dns.AType, dns.AAAAType, dns.TXTType, dns.PTRType, dns.SRVType, dns.NSECType:
				if dns.Find(records, a) < 0 {
					msg.Additional = append(msg.Additional, a)
					records = append(records, a)
				}
			}
		}
	}
}
