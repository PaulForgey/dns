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

var ErrSOA = errors.New("SOA records cannot be interface specific")
var ErrIxfr = errors.New("SOA does not match for IXFR")
var ErrAxfr = errors.New("Mismatched or unexpected SOA values")
var ErrNoSOA = errors.New("zone has no SOA record")
var ErrNoKey = errors.New("zone has no record with this key")
var ErrXferInProgress = errors.New("zone is already transferring")

// the Zones type holds all the zones we know of
type Zones struct {
	sync.RWMutex
	zones map[string]*Zone
}

// the Zone type is a specialization of the resolver Zone with additional information needed by the server
type Zone struct {
	*resolver.Zone
	Primary       string
	AllowQuery    Access
	AllowUpdate   Access
	AllowTransfer Access
	AllowNotify   Access

	// server interaction
	online bool
	r      chan bool // reload
	u      chan bool // update

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
}

func (z *Zone) init() {
	z.r = make(chan bool, 1)
	z.u = make(chan bool, 1)
	z.updateWait = &sync.WaitGroup{}
	z.updateLock = &sync.Mutex{}
	z.updateCond = sync.NewCond(z.updateLock)

	z.db = nsdb.NewMemory() // XXX
	z.keys = make(map[string]nsdb.Db)
	z.keys[""] = z.db
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

// Load loads in a series of records. If an SOA is found, the later in the sequence is used to update serial.
// next returns nil, io.EOF on last record
func (z *Zone) Load(key string, clear bool, next func() (*dns.Record, error)) error {
	z.Lock()
	defer z.Unlock()

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
			if !rec.Name().HasSuffix(z.Name()) {
				return fmt.Errorf("%w: name=%v, suffix=%v", dns.NotZone, rec.Name(), z.Name())
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
func (z *Zone) Save(key string, next func(r *dns.Record) error) error {
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
	if !ok {
		z.RUnlock()
		return ErrNoKey // this is a shallow operation, so wrong key is an error
	}
	z.RUnlock()

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

func (z *Zone) Lookup(
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, []*dns.Record, error) {
	// check the cache
	a, ns, err := z.Zone.Lookup(key, name, rrtype, rrclass)
	if len(a) > 0 || (err != nil && !errors.Is(err, dns.NXDomain)) {
		return a, ns, err
	}

	z.RLock()
	db, ok := z.keys[key]
	if !ok {
		db = z.db
	}
	z.RUnlock()

	// database
	a, ns2, err := z.LookupDb(db, name, rrtype, rrclass)
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
	a, ns2, err = z.LookupDb(z.db, name, rrtype, rrclass)
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

// Reload signals the zone to reload by making the channel in ReloadC() readable
func (z *Zone) Reload() {
	select {
	case z.r <- true:
	default: // don't block
	}
}

// Notify signals the zone to send notifications of an update by making the channel in UpdateC() reable
func (z *Zone) Notify() {
	select {
	case z.u <- true:
	default: // don't block
	}
}

// ReloadC returns a channel which is readable when the zone requests to be reloaded
func (z *Zone) ReloadC() <-chan bool {
	return z.r
}

// NotifyC returns a channel which is readable when the zone requests to send notifications
func (z *Zone) NotifyC() <-chan bool {
	return z.u
}

// HoldUpdates blocks updates from occuring until ReloadUpdates is called
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
func (zs *Zones) Additional(msg *dns.Message, key string, rrclass dns.RRClass) {
	records := make([]*dns.Record, len(msg.Authority), len(msg.Authority)+len(msg.Answers))
	copy(records, msg.Authority)
	records = append(records, msg.Answers...)

	for i := 0; i < len(records); i++ {
		rec := records[i]

		var name dns.Name
		var rrtype dns.RRType

		switch rec.Type() {
		case dns.AType:
			rrtype = dns.AAAAType
			name = rec.Name()

		case dns.AAAAType:
			rrtype = dns.AType
			name = rec.Name()

		default:
			if n, ok := rec.D.(dns.NameRecordType); ok {
				name = n.RName()
				rrtype = dns.AnyType
			}
		}

		if name == nil {
			continue
		}

		// make sure we haven't already put it in
		found := false
		for _, a := range msg.Additional {
			if a.Name().Equal(name) && rrtype.Asks(a.Type()) {
				found = true
				break
			}
		}
		if found {
			continue
		}
		for _, a := range msg.Answers {
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
		answers, _, _ := zone.Lookup(key, name, rrtype, rrclass)
		if len(answers) == 0 {
			return
		}

		for _, a := range answers {
			switch a.Type() {
			case dns.AType, dns.AAAAType, dns.TXTType, dns.PTRType, dns.SRVType:
				msg.Additional = append(msg.Additional, a)
				records = append(records, a)
			}
		}
	}
}
