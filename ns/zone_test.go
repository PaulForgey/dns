package ns

import (
	"testing"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns/test"
	"tessier-ashpool.net/dns/resolver"
)

func TestZoneSearch(t *testing.T) {
	dot := &Zone{Zone: resolver.NewZone(test.NewName("."), true)}
	zone1 := &Zone{Zone: resolver.NewZone(test.NewName("tessier-ashpool.net"), false)}
	zone2 := &Zone{Zone: resolver.NewZone(test.NewName("shoesinonehour.com"), false)}
	zone3 := &Zone{Zone: resolver.NewZone(test.NewName("horses.shoesinonehour.com"), false)}

	zones := NewZones()

	zones.Insert(dot, true)
	zones.Insert(zone1, true)
	zones.Insert(zone2, true)
	zones.Insert(zone3, true)

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

	for _, tc := range tests {
		zone := zones.Find(test.NewName(tc.name))
		if zone != tc.zone {
			var name dns.Name
			if zone != nil {
				name = zone.Name()
			}
			t.Fatalf("expected to find %v in %p, found in %p (%v)", tc.name, tc.zone, zone, name)
		}
		t.Logf("found %v in %v", tc.name, zone.Name())
	}
}
