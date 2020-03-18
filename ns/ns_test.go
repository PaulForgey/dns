package ns

import (
	"context"
	"errors"
	"sync"
	"testing"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns/test"
	"tessier-ashpool.net/dns/nsdb"
	"tessier-ashpool.net/dns/resolver"
)

func exampleZone(origin dns.Name) *Zone {
	z := NewZone(origin, false)
	z.AllowQuery = AllAccess
	z.AllowUpdate = AllAccess
	z.AllowTransfer = AllAccess
	z.AllowNotify = AllAccess

	db := nsdb.NewMemory()
	test.LoadDb(db, origin, `
@ 1h IN SOA hostmaster ns1 (
		1	; serial
		24h	; refresh
		2h	; retry
		1000h	; expire
		48h	; mininum
)
ns1		A 	192.168.0.1
ns2		A 	192.168.0.2

www		CNAME	web
web		A	192.168.0.10
		A	192.168.0.11

@		MX	1   bert
		MX	10  ernie 
		MX	100 mx.example.com

bert		A	192.168.0.20
ernie		A	192.168.0.2

files._smb._tcp	SRV	0 0 445 arbys
arbys		A	192.168.0.30
`)

	z.Attach("", db)
	return z
}

func newServer(t *testing.T, zones *Zones) (*Server, func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	p, err := test.ListenPacketConn("ns")
	if err != nil {
		panic(err)
	}
	s := NewServer(test.NewLog(t), dnsconn.NewPacketConn(p, "testpacket", ""), zones, nil, NoAccess)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		err = s.Serve(ctx)
		wg.Done()
	}()
	return s, func() error {
		cancel()
		wg.Wait()
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		return err
	}
}

func TestServerShutdown(t *testing.T) {
	s, shutdown := newServer(t, NewZones())
	if err := shutdown(); err != nil {
		t.Fatal(err)
	}
	s.Close()
}

type queryCase struct {
	name       dns.Name
	rrtype     dns.RRType
	rcode      dns.RCode
	answers    []*dns.Record
	authority  []*dns.Record
	additional []*dns.Record
}

func compareSection(t *testing.T, q dns.Question, section string, records []*dns.Record, expected []*dns.Record) {
	if len(expected) == 0 {
		return
	}
	if !test.IncludedRecordSet(records, expected) {
		t.Logf("%v did not provide expected %s section", q, section)
		t.Log("got:")
		for _, r := range records {
			t.Log(r)
		}
		t.Log("expected:")
		for _, r := range expected {
			t.Log(r)
		}
		t.FailNow()
	}

}

func TestServerQuery(t *testing.T) {
	zones := NewZones()
	origin := test.NewName("horsegrinders.com")
	zones.Insert(exampleZone(origin), true)
	s, shutdown := newServer(t, zones)

	cases := []*queryCase{
		&queryCase{
			test.NewName("www").Append(origin),
			dns.AType,
			dns.NoError,
			test.NewRecordSet(origin, `
www IN CNAME web
web IN A 192.168.0.10
`),
			nil,
			nil,
		},
	}

	p, err := test.DialPacketConn("client", "ns")
	if err != nil {
		t.Fatal(err)
	}
	res := resolver.NewResolver(zones, dnsconn.NewPacketConn(p, "testpacket", ""), false)

	for _, c := range cases {
		q := dns.NewDNSQuestion(c.name, c.rrtype, dns.INClass)
		msg := &dns.Message{
			Opcode:    dns.StandardQuery,
			Questions: []dns.Question{q},
		}
		resp, err := res.Transact(context.Background(), nil, msg)
		if err != nil && resp == nil {
			t.Fatal(err)
		}
		if !resp.QR {
			t.Fatal("QR is false")
		}
		if resp.ID != msg.ID {
			t.Fatalf("answer id %d != question id %d", resp.ID, msg.ID)
		}
		if resp.RCode != c.rcode {
			t.Fatalf("rcode %v != %v", resp.RCode, c.rcode)
		}

		compareSection(t, q, "answer", resp.Answers, c.answers)
		compareSection(t, q, "authority", resp.Authority, c.authority)
		compareSection(t, q, "additional", resp.Additional, c.additional)
	}

	if err := shutdown(); err != nil {
		t.Fatal(err)
	}

	s.Close()
}
