package resolver

import (
	"reflect"
	"strings"
	"testing"

	"tessier-ashpool.net/dns"
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
		deleted: 0,
		added:   2,
	},
	{
		from:    2,
		to:      3,
		deleted: 1,
		added:   1,
	},
}

func parseTransfer(t *testing.T, serial uint32, records []*dns.Record) []*zoneDelta {
	if len(records) < 2 {
		t.Fatal("no records present")
	}
	soa, ok := records[0].RecordData.(*dns.SOARecord)
	if !ok {
		t.Fatalf("not soa record, got %v", records[0])
	}
	if soa.Serial != serial {
		t.Fatalf("zone transfer should be for serial %d, got %d", serial, soa.Serial)
	}
	last := records[len(records)-1]
	soa, ok = last.RecordData.(*dns.SOARecord)
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
		soa, ok := r.RecordData.(*dns.SOARecord)
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
	z := NewZone(newName(t, "jain.ad.jp"))
	for n, r := range revisions {
		err := z.Decode("", dns.NewTextReader(strings.NewReader(r), z.Name))
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("from %d to %d", n, n+1)

		records := z.Dump(uint32(n), "")
		transfer := parseTransfer(t, uint32(n+1), records)
		if n == 0 {
			if len(transfer) > 0 {
				t.Fatal("initial zone transfer should be full")
			}
		} else {
			if len(transfer) != 1 {
				t.Fatalf("should be 1 delta, got %d", len(transfer))
			}
			if !reflect.DeepEqual(transfer[0], steps[n-1]) {
				t.Fatalf("got %+v, expected %+v", *transfer[0], *steps[n-1])
			}

			t.Logf("%+v", *transfer[0])
		}
	}

	max := len(revisions)
	for n := range revisions {
		t.Logf("from %d to %d", n, max)

		records := z.Dump(uint32(n), "")
		transfer := parseTransfer(t, uint32(max), records)

		parts := max - n
		if parts == max {
			parts = 0
		}

		if len(transfer) != parts {
			t.Fatalf("transfer from %d should have had %d parts", n, parts)
		}

		if n > 0 {
			for i := 0; i < parts; i++ {
				step := steps[n-1+i]
				if !reflect.DeepEqual(transfer[i], step) {
					t.Fatalf("got %+v, expected %+v", *transfer[i], *step)
				}
				t.Logf("%+v", *transfer[i])
			}
		}
	}
}
