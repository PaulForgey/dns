package nsdb

import (
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
)

func compareRecords(t *testing.T, description string, ttl bool, rs1, rs2 []*dns.Record) {
	sort.Slice(rs1, func(i, j int) bool { return rs1[i].Less(rs1[j]) })
	sort.Slice(rs2, func(i, j int) bool { return rs2[i].Less(rs2[j]) })

	equal := len(rs1) == len(rs2)
	for i := 0; i < len(rs1) && equal; i++ {
		equal = rs1[i].Equal(rs2[i])
		if ttl && equal {
			equal = rs1[i].H.TTL() == rs2[i].H.TTL()
		}
	}

	if !equal {
		t.Errorf("record sets are not equal: %s", description)
		t.Errorf("rs1:")
		for _, r := range rs1 {
			t.Errorf("rs1: %v\n", r)
		}
		t.Errorf("rs2:\n")
		for _, r := range rs2 {
			t.Errorf("rs2: %v\n", r)
		}
		t.Fatal()
	}
}

func parseText(t *testing.T, s string) []*dns.Record {
	c := dns.NewTextReader(strings.NewReader(s), nil)
	var records []*dns.Record
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
	return records
}

var data = `
shoes 1h IN TXT "industry"
      TXT       "dead"

host  A         127.0.0.1
host  AAAA      ::1

wild IN A 192.168.0.10
wild IN TXT "wildcard delete"
`

func TestPatch(t *testing.T) {
	remove := parseText(t, `
shoes 1h IN TXT "dead"
host A 127.0.0.1
wild IN ANY
`)
	add := parseText(t, `
host 1h IN A 127.0.0.10
ns1  A 192.168.0.1
`)

	result := parseText(t, `
shoes 1h IN TXT "industry"
host AAAA ::1
host A 127.0.0.10
ns1 A 192.168.0.1
`)

	db := NewMemory()
	if _, err := Load(db, time.Time{}, parseText(t, data)); err != nil {
		t.Fatal(err)
	}
	if _, err := Patch(db, remove, add); err != nil {
		t.Fatal(err)
	}

	var records []*dns.Record
	if err := db.Enumerate(0, func(serial uint32, rr []*dns.Record) error {
		records = append(records, rr...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	compareRecords(t, "result", false, result, records)
}

func TestDelete(t *testing.T) {
	db := NewMemory()
	if _, err := Load(db, time.Time{}, parseText(t, data)); err != nil {
		t.Fatal(err)
	}

	hostName := makeName(t, "host")
	if err := Enter(db, hostName, dns.AType, dns.INClass, nil); err != nil {
		t.Fatal(err)
	}
	rrset, err := Lookup(db, true, hostName, dns.AType, dns.INClass)
	if rrset != nil || err != nil {
		t.Fatalf("expected no error no records, got %v or records", err)
	}
	rrset, err = Lookup(db, false, hostName, dns.AnyType, dns.INClass)
	if rrset == nil || err != nil {
		t.Fatalf("got error %v or no records", err)
	}

	expected := parseText(t, "host 1h IN AAAA ::1")
	compareRecords(t, "remaining AAAA", false, expected, rrset.Records)

	if err := Enter(db, hostName, dns.AnyType, dns.AnyClass, nil); err != nil {
		t.Fatal(err)
	}
	rrset, err = Lookup(db, true, hostName, dns.AAAAType, dns.INClass)
	if rrset != nil || !errors.Is(err, dns.NXDomain) {
		t.Fatalf("expected %v, got %v or records", dns.NXDomain, err)
	}
}
