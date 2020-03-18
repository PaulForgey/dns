package ns

import (
	"errors"
	"testing"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns/test"
)

const updateZone = `
@ 	5m IN SOA ns1 hostmaster 1 24h 2h 1000h 5m

ns1 	A 	192.168.0.1
ns2 	A 	192.168.0.2

rr 	A 	127.0.0.1
   	TXT 	"text"

cr 	CNAME 	rr
`

func testUpdateCase(
	t *testing.T,
	z *Zone,
	prereq, update []*dns.Record,
	q dns.Question,
	results []*dns.Record,
	expect error,
	shouldUpdate bool,
) {
	updated, err := z.Update("", prereq, update)
	if !errors.Is(err, expect) {
		t.Fatalf("expected err %v, got %v", expect, err)
	}
	if updated != shouldUpdate {
		t.Fatalf("expected updated=%v, got %v", shouldUpdate, updated)
	}
	if q == nil {
		return // expected error at this point
	}

	a, _, err := z.Lookup("", q.Name(), q.Type(), q.Class())
	if err != nil {
		if !(errors.Is(err, dns.NXDomain) && len(results) == 0) {
			t.Fatalf("%v: %v", q, err)
		}
	}

	if !test.SameRecordSet(a, results) {
		t.Fatal("results differ")
	}
}

func checkSOA(t *testing.T, z *Zone, serial uint32) {
	soa := z.SOA()
	if soa == nil {
		t.Fatalf("zone %v has no SOA", z.Name())
	}
	soaSerial := soa.D.(*dns.SOARecord).Serial
	if soaSerial != serial {
		t.Fatalf("zone %v expected serial %d, got %d", z.Name(), serial, soaSerial)
	}
}

func TestUpdate(t *testing.T) {
	name := test.NewName("shoesinonehour.com")
	zone := NewZone(name, false)
	loadZoneText(zone, updateZone)

	// simple case: add a resource record
	update := test.NewRecordSet(name, `
host 1h IN A 192.168.0.10
`)
	q := dns.NewDNSQuestion(test.NewName("host").Append(name), dns.AType, dns.INClass)
	testUpdateCase(t, zone, nil, update, q, update, nil, true)

	// add to the same rrset
	update = test.NewRecordSet(name, `
host 1h IN A 192.168.0.11
`)
	expected := test.NewRecordSet(name, `
host 1h IN A 192.168.0.10
host 1h IN A 192.168.0.11
`)
	testUpdateCase(t, zone, nil, update, q, expected, nil, true)

	// remove the .11
	update = test.NewRecordSet(name, `
host 0 NONE A 192.168.0.11
`)
	expected = test.NewRecordSet(name, `
host 1h IN A 192.168.0.10
`)
	testUpdateCase(t, zone, nil, update, q, expected, nil, true)

	// remove everything
	update = test.NewRecordSet(name, `
host 0 ANY ANY
`)
	testUpdateCase(t, zone, nil, update, q, nil, nil, true)

	// try to update a CNAME with a non-CNAME
	q = dns.NewDNSQuestion(test.NewName("cr").Append(name), dns.AType, dns.INClass)
	update = test.NewRecordSet(name, `
cr 1h IN A 127.0.0.1
`)
	expected = test.NewRecordSet(name, `
cr 5m IN CNAME rr
`)
	testUpdateCase(t, zone, nil, update, q, expected, nil, false)

	// now update the CNAME with a CNAME
	update = test.NewRecordSet(name, `
cr 1h IN CNAME host
`)
	testUpdateCase(t, zone, nil, update, q, update, nil, true)

	// update record with same data
	q = dns.NewDNSQuestion(test.NewName("ns2").Append(name), dns.AType, dns.INClass)
	update = test.NewRecordSet(name, `
ns2 5m IN A 192.168.0.2
`)
	testUpdateCase(t, zone, nil, update, q, update, nil, false)

	// add a record outside the zone (expect NotZone)
	update = test.NewRecordSet(nil, `
ns2.horsegrinders.com. 5m IN A 192.168.0.1
`)
	testUpdateCase(t, zone, nil, update, nil, nil, dns.NotZone, false)

	// first time asking for SOA after all these updates, should be serial 2
	checkSOA(t, zone, 2)

	// now update SOA serial to 10
	update = test.NewRecordSet(name, `
@ IN SOA ns1 hostmaster 10 24h 2h 1000h 5m
`)
	q = dns.NewDNSQuestion(name, dns.SOAType, dns.INClass)
	testUpdateCase(t, zone, nil, update, q, update, nil, true)
	checkSOA(t, zone, 10) // should still be 10 and not autoincremented
}

func TestPrereqUpdate(t *testing.T) {
	name := test.NewName("shoesinonehour.com")
	zone := NewZone(name, false)
	loadZoneText(zone, updateZone)

	// update if record not present (should add)
	update := test.NewRecordSet(name, `
shoes 1h IN TXT "industry"
`)
	prereq := test.NewRecordSet(name, `
shoes 1h NONE TXT
`)
	q := dns.NewDNSQuestion(test.NewName("shoes").Append(name), dns.TXTType, dns.INClass)
	testUpdateCase(t, zone, prereq, update, q, update, nil, true)

	// same update again should fail YXRRset and original results
	results := update
	update = test.NewRecordSet(name, `
shoes 1h IN TXT "dead"
`)
	testUpdateCase(t, zone, prereq, update, q, results, dns.YXRRSet, false)

	// fail update with prereq not caring about type, should fail with YXDOMAIN
	prereq = test.NewRecordSet(name, `
shoes 1h NONE ANY
`)
	testUpdateCase(t, zone, prereq, update, q, results, dns.YXDomain, false)

	// update if rrset exists, should fail with NXRRSet
	prereq = test.NewRecordSet(name, `
bozo 1h ANY TXT
`)
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXRRSet, false)

	// update if name exists, should fail with NXDomain
	prereq = test.NewRecordSet(name, `
bozo 1h ANY ANY
`)
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXDomain, false)

	// update if rrset with value exists, add record
	update = test.NewRecordSet(name, `
rr 1h IN A 127.0.0.10
`)
	prereq = test.NewRecordSet(name, `
rr 5m IN A 127.0.0.1
`)
	results = test.NewRecordSet(name, `
rr 5m IN A 127.0.0.1
rr 1h IN A 127.0.0.10
`)
	q = dns.NewDNSQuestion(test.NewName("rr").Append(name), dns.AType, dns.INClass)
	testUpdateCase(t, zone, prereq, update, q, results, nil, true)

	// update if rrset with value exists, should fail with NXRRset
	prereq = test.NewRecordSet(name, `
rr 1h IN A 192.168.0.1
`)
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXRRSet, false)
}
