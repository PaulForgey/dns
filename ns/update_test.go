package ns

import (
	"errors"
	"sort"
	"strings"
	"testing"

	"tessier-ashpool.net/dns"
)

const updateZone = `
@ 	5m IN SOA ns1 hostmaster 1 24h 2h 1000h 5m

ns1 	A 	192.168.0.1
ns2 	A 	192.168.0.2

rr 	A 	127.0.0.1
   	TXT 	"text"

cr 	CNAME 	rr
`

func recordWithString(t *testing.T, name dns.Name, data string) *dns.Record {
	c := dns.NewTextReader(strings.NewReader(data), name)
	rr := &dns.Record{}
	err := c.Decode(rr)
	if err != nil {
		t.Fatalf("error parsing %s: %v", data, err)
	}
	return rr
}

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

	sort.Slice(a, func(i, j int) bool {
		return a[i].Less(a[j])
	})
	sort.Slice(results, func(i, j int) bool {
		return results[i].Less(results[j])
	})

	if len(a) != len(results) {
		t.Fatalf("got %d answers, expected %d", len(a), len(results))
	}
	for i := range a {
		if !a[i].Equal(results[i]) {
			t.Fatalf("%v != %v", a[i], results[i])
		}
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
	name := nameWithString(t, "shoesinonehour.com")
	zone := NewZone(name, false)
	loadZoneText(t, zone, updateZone)

	// simple case: add a resource record
	update := []*dns.Record{
		recordWithString(t, name, "host 1h IN A 192.168.0.10"),
	}

	q := dns.NewDNSQuestion(nameWithString(t, "host").Append(name), dns.AType, dns.INClass)
	testUpdateCase(t, zone, nil, update, q, update, nil, true)

	// add to the same rrset
	update = []*dns.Record{
		recordWithString(t, name, "host 1h IN A 192.168.0.11"),
	}
	expected := []*dns.Record{
		recordWithString(t, name, "host 1h IN A 192.168.0.10"),
		recordWithString(t, name, "host 1h IN A 192.168.0.11"),
	}
	testUpdateCase(t, zone, nil, update, q, expected, nil, true)

	// remove the .11
	update = []*dns.Record{
		recordWithString(t, name, "host 0 NONE A 192.168.0.11"),
	}
	expected = []*dns.Record{
		recordWithString(t, name, "host 1h IN A 192.168.0.10"),
	}
	testUpdateCase(t, zone, nil, update, q, expected, nil, true)

	// remove everything
	update = []*dns.Record{
		recordWithString(t, name, "host 0 ANY ANY"),
	}
	testUpdateCase(t, zone, nil, update, q, nil, nil, true)

	// try to update a CNAME with a non-CNAME
	q = dns.NewDNSQuestion(nameWithString(t, "cr").Append(name), dns.AType, dns.INClass)
	update = []*dns.Record{
		recordWithString(t, name, "cr 1h IN A 127.0.0.1"),
	}
	expected = []*dns.Record{
		recordWithString(t, name, "cr 5m IN CNAME rr"),
	}
	testUpdateCase(t, zone, nil, update, q, expected, nil, false)

	// now update the CNAME with a CNAME
	update = []*dns.Record{
		recordWithString(t, name, "cr 1h IN CNAME host"),
	}
	testUpdateCase(t, zone, nil, update, q, update, nil, true)

	// update record with same data
	q = dns.NewDNSQuestion(nameWithString(t, "ns2").Append(name), dns.AType, dns.INClass)
	update = []*dns.Record{
		recordWithString(t, name, "ns2 5m IN A 192.168.0.2"),
	}
	testUpdateCase(t, zone, nil, update, q, update, nil, false)

	// add a record outside the zone (expect NotZone)
	update = []*dns.Record{
		recordWithString(t, nil, "ns2.horsegrinders.com. 5m IN A 192.168.0.1"),
	}
	testUpdateCase(t, zone, nil, update, nil, nil, dns.NotZone, false)

	// first time asking for SOA after all these updates, should be serial 2
	checkSOA(t, zone, 2)

	// now update SOA serial to 10
	update = []*dns.Record{
		recordWithString(t, name, "@ IN SOA ns1 hostmaster 10 24h 2h 1000h 5m"),
	}
	q = dns.NewDNSQuestion(name, dns.SOAType, dns.INClass)
	testUpdateCase(t, zone, nil, update, q, update, nil, true)
	checkSOA(t, zone, 10) // should still be 10 and not autoincremented
}

func TestPrereqUpdate(t *testing.T) {
	name := nameWithString(t, "shoesinonehour.com")
	zone := NewZone(name, false)
	loadZoneText(t, zone, updateZone)

	// update if record not present (should add)
	update := []*dns.Record{
		recordWithString(t, name, "shoes 1h IN TXT \"industry\""),
	}
	prereq := []*dns.Record{
		recordWithString(t, name, "shoes 1h NONE TXT"),
	}

	q := dns.NewDNSQuestion(nameWithString(t, "shoes").Append(name), dns.TXTType, dns.INClass)
	testUpdateCase(t, zone, prereq, update, q, update, nil, true)

	// same update again should fail YXRRset and original results
	results := update
	update = []*dns.Record{
		recordWithString(t, name, "shoes 1h IN TXT \"dead\""),
	}
	testUpdateCase(t, zone, prereq, update, q, results, dns.YXRRSet, false)

	// fail update with prereq not caring about type, should fail with YXDOMAIN
	prereq = []*dns.Record{
		recordWithString(t, name, "shoes 1h NONE ANY"),
	}
	testUpdateCase(t, zone, prereq, update, q, results, dns.YXDomain, false)

	// update if rrset exists, should fail with NXRRSet
	prereq = []*dns.Record{
		recordWithString(t, name, "bozo 1h ANY TXT"),
	}
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXRRSet, false)

	// update if name exists, should fail with NXDomain
	prereq = []*dns.Record{
		recordWithString(t, name, "bozo 1h ANY ANY"),
	}
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXDomain, false)

	// update if rrset with value exists, add record
	update = []*dns.Record{
		recordWithString(t, name, "rr 1h IN A 127.0.0.10"),
	}
	prereq = []*dns.Record{
		recordWithString(t, name, "rr 5m IN A 127.0.0.1"),
	}
	results = []*dns.Record{
		recordWithString(t, name, "rr 5m IN A 127.0.0.1"),
		recordWithString(t, name, "rr 1h IN A 127.0.0.10"),
	}
	q = dns.NewDNSQuestion(nameWithString(t, "rr").Append(name), dns.AType, dns.INClass)
	testUpdateCase(t, zone, prereq, update, q, results, nil, true)

	// update if rrset with value exists, should fail with NXRRset
	prereq = []*dns.Record{
		recordWithString(t, name, "rr 1h IN A 192.168.0.1"),
	}
	testUpdateCase(t, zone, prereq, update, q, results, dns.NXRRSet, false)
}
