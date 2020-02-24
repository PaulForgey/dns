package nsdb

import (
	"errors"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
)

var cacheData = `
one  4s IN A 192.168.0.1
two        A 192.168.0.2
red  2s    A 192.168.0.3
blue 3s    A 192.168.0.4
`

// update 2s later
var cacheUpdate = `
two  4s IN A 192.168.0.20
blue 0s    A 192.168.0.4
`

var cacheResult = `
one  2s IN A 192.168.0.1  ; 4s - 2s = 2s
two  4s    A 192.168.0.20 ; freshly upated to 4s
two  2s    A 192.168.0.2  ; other rdata for two aged 2 seconds
                          ; red times out entirely
blue 1s    A 192.168.0.4  ; ttl 0 -> 1
`

func TestCacheUpdate(t *testing.T) {
	now := time.Now()
	db := NewCache()

	if _, err := Load(db, now, parseText(t, cacheData)); err != nil {
		t.Fatal(err)
	}

	now = now.Add(2 * time.Second)
	for _, r := range parseText(t, cacheUpdate) {
		result, err := db.lookup(r.H.Name(), now)
		if err != nil {
			t.Fatal(err)
		}
		result = result.Copy()
		result.Load(now, []*dns.Record{r})
		err = db.Enter(r.H.Name(), result)
		if err != nil {
			t.Fatal(err)
		}
	}

	var records []*dns.Record

	for _, n := range []string{"one", "two", "red", "blue"} {
		name := makeName(t, n)
		result, err := db.lookup(name, now)
		if err != nil && !errors.Is(err, dns.NXDomain) {
			t.Fatal(err)
		}
		if result != nil {
			for _, v := range result.Map {
				records = append(records, v.Records...)
			}
		}
	}

	compareRecords(t, "cache contents vs expected", true, records, parseText(t, cacheResult))
}
