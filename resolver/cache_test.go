package resolver

import (
	"net"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
)

func nameWithString(t *testing.T, s string) dns.Name {
	name, err := dns.NameWithString(s)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func makeRecordSet(t *testing.T, alt bool) []*dns.Record {
	var adata [4]byte
	var aaaadata [16]byte

	if alt {
		copy(adata[:], []byte{127, 0, 0, 2})
		copy(aaaadata[:], net.ParseIP("::2"))
	} else {
		copy(adata[:], []byte{127, 0, 0, 1})
		copy(aaaadata[:], net.ParseIP("::1"))
	}

	return []*dns.Record{
		&dns.Record{
			RecordHeader: dns.RecordHeader{
				Name:  nameWithString(t, "tessier-ashpool.net"),
				Class: dns.INClass,
				TTL:   10 * time.Second,
			},
			RecordData: &dns.NSRecord{
				Name: nameWithString(t, "ns1.tessier-ashpool.net"),
			},
		},
		&dns.Record{
			RecordHeader: dns.RecordHeader{
				Name:  nameWithString(t, "ns1.tessier-ashpool.net"),
				Class: dns.INClass,
				TTL:   5 * time.Second,
			},
			RecordData: &dns.ARecord{
				Address: adata,
			},
		},
		&dns.Record{
			RecordHeader: dns.RecordHeader{
				Name:  nameWithString(t, "ns1.tessier-ashpool.net"),
				Class: dns.INClass,
				TTL:   5 * time.Second,
			},
			RecordData: &dns.AAAARecord{
				Address: aaaadata,
			},
		},
	}
}

func TestCacheEnterAndGet(t *testing.T) {
	c := NewCache(nil)

	c.Enter(time.Time{}, false, makeRecordSet(t, false))

	records := c.Get(time.Now(), nameWithString(t, "tessier-ashpool.net"), dns.NSType, dns.INClass)
	for _, record := range records {
		t.Log(record)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if !records[0].RecordHeader.Authoritative {
		t.Fatalf("should be authoritative")
	}

	records = c.Get(time.Now(), nameWithString(t, "ns1.tessier-ashpool.net"), dns.AnyType, dns.INClass)
	for _, record := range records {
		t.Log(record)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
}

func TestCacheExpire(t *testing.T) {
	c := NewCache(nil)

	now := time.Now()
	c.Enter(now, false, makeRecordSet(t, false))

	now = now.Add(5 * time.Second)
	records := c.Get(now, nameWithString(t, "tessier-ashpool.net"), dns.AnyType, dns.INClass)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	t.Log(records[0])
	if records[0].RecordHeader.TTL != 5*time.Second {
		t.Fatalf("TTL=%v, expected 5s", records[0].RecordHeader.TTL)
	}

	records = c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.NSType, dns.INClass)
	if len(records) > 0 {
		t.Fatalf("expected no records, got %d", len(records))
	}
}

func TestCacheOverwrite(t *testing.T) {
	c := NewCache(nil)
	now := time.Now()

	c.Enter(time.Time{}, false, makeRecordSet(t, false))

	records := c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	c.Enter(now, false, makeRecordSet(t, true))

	records = c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// should be original record
	ip := records[0].RecordData.(dns.IPRecordType).IP()
	if !ip.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("got %v, expected 127.0.0.1", ip)
	}
	// should be authoritative
	if !records[0].RecordHeader.Authoritative {
		t.Fatalf("should be authoritative")
	}

	c.Enter(time.Time{}, false, makeRecordSet(t, true))
	records = c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	// should be new record
	ip = records[0].RecordData.(dns.IPRecordType).IP()
	if !ip.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatalf("got %v, expected 127.0.0.2", ip)
	}
	// should be authoritative
	if !records[0].RecordHeader.Authoritative {
		t.Fatalf("should be authoritative")
	}
}

func TestNegativeCache(t *testing.T) {
	c := NewCache(nil)
	now := time.Now()

	c.Enter(now, true, []*dns.Record{&dns.Record{
		RecordHeader: dns.RecordHeader{
			Name:  nameWithString(t, "ns2.tessier-ashpool.net"),
			TTL:   10 * time.Second,
			Type:  dns.AType,
			Class: dns.INClass,
		},
		RecordData: nil,
	},
	})

	now = now.Add(5 * time.Second)

	records := c.Get(now, nameWithString(t, "ns2.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].RecordHeader.Authoritative {
		t.Fatalf("record should not be authoritative")
	}
	if records[0].RecordHeader.TTL != 5*time.Second {
		t.Fatalf("expected TTL of 5s, got %v", records[0].TTL)
	}
	if records[0].RecordData != nil {
		t.Fatalf("expected nil RecordData, got %v", records[0].RecordData)
	}
}

func TestMerge(t *testing.T) {
	c := NewCache(nil)
	now := time.Now()

	c.Enter(now, true, makeRecordSet(t, false))

	now = now.Add(3 * time.Second)
	c.Enter(now, true, makeRecordSet(t, true))

	records := c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)

	// ns1.tessier-ashpool.net should have two A records; 2 A 127.0.0.1 and 5 A 127.0.0.2
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	var seen1, seen2 bool
	for _, r := range records {
		ip := r.RecordData.(dns.IPRecordType).IP()
		switch r.RecordHeader.TTL {
		case 2 * time.Second:
			if !ip.Equal(net.ParseIP("127.0.0.1")) {
				t.Fatalf("expected 127.0.0.1, got %v", r)
			}
			seen1 = true
		case 5 * time.Second:
			if !ip.Equal(net.ParseIP("127.0.0.2")) {
				t.Fatalf("expected 127.0.0.2, got %v", r)
			}
			seen2 = true
		default:
			t.Fatal(r)
		}
	}
	if !(seen1 && seen2) {
		t.Fatal("did not see both records")
	}

	c.Enter(now, true, makeRecordSet(t, false))

	// now both should have TTL 5
	records = c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	for _, r := range records {
		if r.RecordHeader.TTL != 5*time.Second {
			t.Fatalf("TTL should be 5s, got %v", r)
		}
	}
}

func TestOverwrite(t *testing.T) {
	c := NewCache(nil)
	now := time.Now()

	c.Enter(now, false, makeRecordSet(t, false))
	c.Enter(now, false, makeRecordSet(t, true))

	// should have two records, the original having a TTL of 1
	records := c.Get(now, nameWithString(t, "ns1.tessier-ashpool.net"), dns.AType, dns.INClass)
	if len(records) != 2 {
		t.Fatalf("expected 2 recoreds, got %d", len(records))
	}
	for _, r := range records {
		t.Log(r)
		ip := r.RecordData.(dns.IPRecordType).IP()
		switch r.RecordHeader.TTL {
		case 5 * time.Second:
			if !ip.Equal(net.ParseIP("127.0.0.2")) {
				t.Fatalf("expected 127.0.0.2, got %v", r)
			}
		case 1 * time.Second:
			if !ip.Equal(net.ParseIP("127.0.0.1")) {
				t.Fatalf("expected 127.0.0.1, got %v", r)
			}
		default:
			t.Fatalf("got unexpected record %v", r)
		}
	}
}
