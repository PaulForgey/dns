package resolver

import (
	"testing"

	"tessier-ashpool.net/dns"
)

func newName(t *testing.T, n string) dns.Name {
	name, err := dns.NameWithString(n)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestZoneSearch(t *testing.T) {
	dot := NewZone(newName(t, "."))
	zone1 := NewZone(newName(t, "tessier-ashpool.net"))
	zone2 := NewZone(newName(t, "shoesinonehour.com"))
	zone3 := NewZone(newName(t, "horses.shoesinonehour.com"))

	zones := NewZones()

	zones.Insert(dot)
	zones.Insert(zone1)
	zones.Insert(zone2)
	zones.Insert(zone3)

	// expect to find these names in this zone
	tests := []struct {
		name string
		zone *Zone
	}{
		{"tessier-ashpool.net", zone1},
		{"delegate.tessier-ashpool.net", zone1},
		{"horsegrinders.com", dot},
		{"x.shoesinonehour.com", zone2},
		{"x.horses.shoesinonehour.com", zone3},
		{"horses.shoesinonehour.com", zone3},
	}

	for _, test := range tests {
		zone := zones.Find(newName(t, test.name))
		if zone != test.zone {
			var name dns.Name
			if zone != nil {
				name = zone.Name
			}
			t.Fatalf("expected to find %v in %p, found in %p (%v)", test.name, test.zone, zone, name)
		}
		t.Logf("found %v in %v", test.name, zone.Name)
	}
}
