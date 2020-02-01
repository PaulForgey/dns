package nsdb

import (
	"fmt"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
)

var revisions = []string{
	// serial 1
	`
shoes     1h IN TXT "industry"
          TXT       "dead"

host      A         192.168.0.1
`,
	// serial 2
	`
shoes     1h IN TXT "industry"

host      A         192.168.0.1
`,
	// serial 3
	`
shoes     1h IN TXT "industry"

otherhost A         192.168.0.10
`,
}

// expected revisions between if cleared
var deltas = []struct {
	remove string
	add    string
}{
	// serial 1
	{
		remove: "",
		add:    revisions[0],
	},
	// serial 2
	{
		remove: `
shoes 1h IN TXT "dead"
`,
		add: "",
	},
	// serial 3
	{
		remove: `
host 1h IN A 192.168.0.1
`,
		add: `
otherhost 1h IN A 192.168.0.10
`,
	},
}

// if all three revisions are loaded without clearing, final result. This expected duplicates.
const combined = `
shoes     1h IN TXT "industry"
shoes     TXT       "dead"
host      A         192.168.0.1
otherhost A         192.168.0.10
`

func TestLoad(t *testing.T) {
	m := NewMemory()

	for _, s := range revisions {
		records := parseText(t, s)
		if _, err := Load(m, time.Time{}, records); err != nil {
			t.Fatal(err)
		}
	}

	expected := parseText(t, combined)
	var records []*dns.Record

	if err := m.Enumerate(0, func(serial uint32, r []*dns.Record) error {
		records = append(records, r...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	compareRecords(t, "zone contents", expected, records)
}

func TestDelta(t *testing.T) {
	m := NewMemory()

	for i, s := range revisions {
		m.Clear()
		records := parseText(t, s)
		if _, err := Load(m, time.Time{}, records); err != nil {
			t.Fatal(err)
		}

		var add []*dns.Record
		var remove []*dns.Record

		if err := m.Enumerate(uint32(i), func(serial uint32, r []*dns.Record) error {
			if serial != 0 {
				if serial != uint32(i) {
					t.Fatalf("remove should be from serial %d, got %d", i, serial)
				}
				remove = append(remove, r...)
			} else {
				add = append(add, r...)
			}
			return nil

		}); err != nil {
			t.Fatal(err)
		}

		expectedRemove := parseText(t, deltas[i].remove)
		expectedAdd := parseText(t, deltas[i].add)

		compareRecords(t, fmt.Sprintf("remove from %d", i), expectedRemove, remove)
		compareRecords(t, fmt.Sprintf("add from %d:", i), expectedAdd, add)

		if err := m.Snapshot(uint32(i + 1)); err != nil {
			t.Fatal(err)
		}
	}
}

func makeName(t *testing.T, s string) dns.Name {
	name, err := dns.NameWithString(s)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestLookup(t *testing.T) {
	m := NewMemory()
	records := parseText(t, `
shoes 1h IN TXT "industry"
dead IN CNAME shoes
host IN A 127.0.0.1
host IN AAAA ::1
`)

	if _, err := Load(m, time.Time{}, records); err != nil {
		t.Fatal(err)
	}

	shoes := parseText(t, `
shoes IN TXT "industry"
`)
	dead := parseText(t, `
dead IN CNAME shoes
`)
	host := parseText(t, `
host IN A 127.0.0.1
host IN AAAA ::1
`)

	lookups := []struct {
		name    dns.Name
		rrtype  dns.RRType
		rrclass dns.RRClass
		expect  []*dns.Record
	}{
		{
			name:    makeName(t, "shoes"),
			rrtype:  dns.TXTType,
			rrclass: dns.INClass,
			expect:  shoes,
		},
		{
			name:    makeName(t, "dead"),
			rrtype:  dns.AType,
			rrclass: dns.INClass,
			expect:  dead,
		},
		{
			name:    makeName(t, "dead"),
			rrtype:  dns.AType,
			rrclass: dns.AnyClass,
			expect:  dead,
		},
		{
			name:    makeName(t, "host"),
			rrtype:  dns.AnyType,
			rrclass: dns.INClass,
			expect:  host,
		},
	}

	for i, l := range lookups {
		rrset, err := Lookup(m, false, l.name, l.rrtype, l.rrclass)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if rrset == nil {
			t.Fatalf("case %d: no records", i)
		}
		compareRecords(t, fmt.Sprintf("case %d", i), rrset.Records, l.expect)
	}
}
