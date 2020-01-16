package nsdb

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
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
shoes     TXT       "industry"
shoes     TXT       "industry"
shoes     TXT       "dead"
host      A         192.168.0.1
host      A         192.168.0.1
otherhost A         192.168.0.10
`

func compareRecords(t *testing.T, description string, rs1, rs2 []*dns.Record) {
	sort.Slice(rs1, func(i, j int) bool { return rs1[i].Less(rs1[j]) })
	sort.Slice(rs2, func(i, j int) bool { return rs2[i].Less(rs2[j]) })

	equal := len(rs1) == len(rs2)
	for i := 0; i < len(rs1) && equal; i++ {
		equal = rs1[i].Equal(rs2[i])
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

func TestLoad(t *testing.T) {
	m := NewMemory()

	for _, s := range revisions {
		records := parseText(t, s)
		if err := Load(m, time.Time{}, records); err != nil {
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
		if err := Load(m, time.Time{}, records); err != nil {
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
