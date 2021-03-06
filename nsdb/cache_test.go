package nsdb

import (
	"errors"
	"fmt"
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
		result, err := db.lookup(now, r.H.Name())
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
		result, err := db.lookup(now, name)
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

func TestNegativeCache(t *testing.T) {
	now := time.Now()
	db := NewCache()
	name := makeName(t, "negative")

	err := db.Enter(name, &RRMap{Negative: now.Add(5)})
	if err != nil {
		t.Fatal(err)
	}

	rrmap, err := db.lookup(now, name)
	if !errors.Is(err, ErrNegativeAnswer) {
		t.Fatalf("expected %v, got %v", ErrNegativeAnswer, err)
	}
	var rcode dns.RCode
	if !errors.As(err, &rcode) {
		t.Fatalf("%T is not RCode", err)
	}
	if rcode != dns.NXDomain {
		t.Fatalf("expected %v, got %v", dns.NXDomain, rcode)
	}

	if rrmap != nil {
		t.Fatal("rrmap != nil")
	}

	now = now.Add(5 * time.Second)

	rrmap, err = db.lookup(now, name)
	if !errors.Is(err, dns.NXDomain) {
		t.Fatalf("expected %v, got %v", dns.NXDomain, err)
	}
	if errors.Is(err, ErrNegativeAnswer) {
		t.Fatalf("%v is still %v", err, ErrNegativeAnswer)
	}
	if rrmap != nil {
		t.Fatal("rrmap != nil")
	}
}

func generateRecords(t *testing.T, i, j int) []*dns.Record {
	records := make([]*dns.Record, 0, (j-i)+1)
	for n := i; n <= j; n++ {
		txt := fmt.Sprintf("record%d", n)
		name := makeName(t, txt)
		records = append(records, &dns.Record{
			H: dns.NewHeader(name, dns.TXTType, dns.INClass, time.Hour),
			D: &dns.TXTRecord{Text: []string{"value"}},
		})
	}
	return records
}

func TestCacheLimit(t *testing.T) {
	MaxItems = 10
	LowItems = 5

	db := NewCache()

	_, err := Load(db, time.Now(), generateRecords(t, 1, MaxItems))
	if err != nil {
		t.Fatal(err)
	}

	if len(db.items) != MaxItems {
		t.Fatalf("expected %d items, got %d", MaxItems, len(db.items))
	}

	_, err = Load(db, time.Now(), generateRecords(t, MaxItems+1, MaxItems+1))
	if len(db.items) != LowItems {
		t.Fatalf("expected %d items, got %d", LowItems, len(db.items))
	}
}
