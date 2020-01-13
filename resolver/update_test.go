package resolver

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
	q *dns.Question,
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

	a, _, err := z.Lookup("", q.QName, q.QType, q.QClass)
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

func TestZoneUpdate(t *testing.T) {
	name := nameWithString(t, "shoesinonehour.com")
	zone := NewZone(name, false)
	c := dns.NewTextReader(strings.NewReader(updateZone), name)
	err := zone.Decode("", false, c)
	if err != nil {
		t.Fatalf("cannot load zone %v: %v", name, err)
	}

	// simple case: add a resource record
	update := []*dns.Record{
		recordWithString(t, name, "host 1h IN A 192.168.0.10"),
	}

	q := &dns.Question{
		QName:  nameWithString(t, "host").Append(name),
		QType:  dns.AType,
		QClass: dns.INClass,
	}
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
	q = &dns.Question{
		QName:  nameWithString(t, "cr").Append(name),
		QType:  dns.AType,
		QClass: dns.INClass,
	}
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
	q = &dns.Question{
		QName:  nameWithString(t, "ns2").Append(name),
		QType:  dns.AType,
		QClass: dns.INClass,
	}
	update = []*dns.Record{
		recordWithString(t, name, "ns2 5m IN A 192.168.0.2"),
	}
	testUpdateCase(t, zone, nil, update, q, update, nil, false)
}
