package ns

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/nsdb"
)

var revisions = []string{
	`
JAIN.AD.JP.       1 IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
    				  1 600 600 3600000 604800 )
		    IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
NEZU.JAIN.AD.JP.    IN A   133.69.136.5
`,

	`
jain.ad.jp.       1 IN SOA ns.jain.ad.jp. mohta.jain.ad.jp. (
                                  2 600 600 3600000 604800 )
		    IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.4
		    IN A   192.41.197.2
`,

	`
JAIN.AD.JP.       1 IN SOA ns.jain.ad.jp. mohta.jain.ad.jp. (
                                  3 600 600 3600000 604800 )
                    IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3
                    IN A   192.41.197.2
`,
}

type zoneDelta struct {
	from, to       uint32
	deleted, added int
}

var steps = []*zoneDelta{
	{
		from:    1,
		to:      2,
		deleted: 1,
		added:   2,
	},
	{
		from:    2,
		to:      3,
		deleted: 1,
		added:   1,
	},
}

func compareZone(t *testing.T, z1, z2 *Zone) {
	var r1 []*dns.Record
	z1.Dump(0, dns.AnyClass, func(r *dns.Record) error {
		r1 = append(r1, r)
		return nil
	})

	for _, r := range r1 {
		r2, _, _ := z2.Lookup("", r.Name(), r.Type(), r.Class())
		if len(r2) < 1 {
			t.Fatalf("z2 did not contain %v %v %v", r.Name(), r.Type(), r.Class())
		}
		found := false
		for _, rr := range r2 {
			if reflect.DeepEqual(rr.D, r.D) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("did not find %v in z2", r)
		}
	}
}

func reloadZoneText(t *testing.T, z *Zone, db nsdb.Db, s string) {
	if err := db.Clear(); err != nil {
		t.Fatal(err)
	}
	c := dns.NewTextReader(strings.NewReader(s), z.Name())
	records := []*dns.Record{}
	for {
		r := &dns.Record{}
		if err := c.Decode(r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatal(err)
		}
		records = append(records, r)
	}
	if _, err := nsdb.Load(db, time.Time{}, records); err != nil {
		t.Fatal(err)
	}
	if err := z.Attach("", db); err != nil {
		t.Fatal(err)
	}
}

func loadZoneText(t *testing.T, z *Zone, s string) {
	m := nsdb.NewMemory()
	reloadZoneText(t, z, m, s)
}

func TestIXFR(t *testing.T) {
	z := NewZone(nameWithString(t, "jain.ad.jp"), false)
	m := nsdb.NewMemory()
	for i, r := range revisions {
		reloadZoneText(t, z, m, r)
		if _, err := z.Dump(0, dns.AnyClass, func(r *dns.Record) error {
			fmt.Println(i, r)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	// secondary with initial revision
	zz := NewZone(nameWithString(t, "jain.ad.jp"), false)
	loadZoneText(t, zz, revisions[0])

	// request ixfr from 1 -> current
	var ixfr []*dns.Record
	z.Dump(1, dns.AnyClass, func(r *dns.Record) error {
		ixfr = append(ixfr, r)
		fmt.Println(r)
		return nil
	})

	n := 0
	err := zz.Xfer(true, func() (*dns.Record, error) {
		if n < len(ixfr) {
			rec := ixfr[n]
			n++
			return rec, nil
		}
		return nil, io.EOF
	})
	if err != nil {
		t.Fatal(err)
	}

	compareZone(t, z, zz)
	compareZone(t, zz, z)
}

func parseTransfer(t *testing.T, serial uint32, records []*dns.Record) []*zoneDelta {
	if len(records) < 1 {
		t.Fatal("no records present")
	}
	soa, ok := records[0].D.(*dns.SOARecord)
	if !ok {
		t.Fatalf("not soa record, got %v", records[0])
	}
	if soa.Serial != serial {
		t.Fatalf("zone transfer should be for serial %d, got %d", serial, soa.Serial)
	}
	if len(records) == 1 {
		return nil
	}

	last := records[len(records)-1]
	soa, ok = last.D.(*dns.SOARecord)
	if !ok {
		t.Fatalf("not soa record, got %v", last)
	}
	if soa.Serial != serial {
		t.Fatalf("zone transfer should be for serial %d, got %d", serial, soa.Serial)
	}

	var delta *zoneDelta
	var transfer []*zoneDelta
	var from bool

	for _, r := range records[1 : len(records)-1] {
		soa, ok := r.D.(*dns.SOARecord)
		if ok {
			if from {
				delta.to = soa.Serial
				from = false
			} else {
				if delta != nil {
					transfer = append(transfer, delta)
				}
				from = true
				delta = &zoneDelta{
					from: soa.Serial,
				}
			}
		} else if delta != nil {
			if from {
				delta.deleted++
			} else {
				delta.added++
			}
		}
	}
	if delta != nil {
		transfer = append(transfer, delta)
	}

	return transfer
}

func TestZoneDump(t *testing.T) {
	z := NewZone(nameWithString(t, "jain.ad.jp"), false)
	m := nsdb.NewMemory()
	for n, r := range revisions {
		reloadZoneText(t, z, m, r)

		t.Logf("from %d to %d", n, n+1)

		var records []*dns.Record
		z.Dump(uint32(n), dns.AnyClass, func(r *dns.Record) error {
			records = append(records, r)
			return nil
		})
		transfer := parseTransfer(t, uint32(n+1), records)
		if n == 0 {
			if len(transfer) > 0 {
				t.Fatal("initial zone transfer should be full")
			}
		} else {
			if len(transfer) != 1 {
				t.Fatalf("%d: should be 1 delta, got %d", n, len(transfer))
			}
			if !reflect.DeepEqual(transfer[0], steps[n-1]) {
				t.Fatalf("%d: got %+v, expected %+v", n, *transfer[0], *steps[n-1])
			}

			t.Logf("%d: %+v", n, *transfer[0])
		}
	}
}