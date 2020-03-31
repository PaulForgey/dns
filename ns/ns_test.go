package ns

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns/test"
	"tessier-ashpool.net/dns/nsdb"
	"tessier-ashpool.net/dns/resolver"
)

func newZone(origin dns.Name) *Zone {
	z := NewZone(origin, false)
	z.AllowQuery = AllAccess
	z.AllowUpdate = AllAccess
	z.AllowTransfer = AllAccess
	z.AllowNotify = AllAccess

	db := nsdb.NewMemory()
	z.Attach("", db)

	return z
}

func exampleZone(origin dns.Name) *Zone {
	z := newZone(origin)
	db := z.Db("")

	test.LoadDb(db, origin, `
@ 1h IN 	SOA hostmaster ns1 (
		1	; serial
		24h	; refresh
		2h	; retry
		1000h	; expire
		48h	; mininum
)

@		NS	ns1
		NS	ns2
ns1		A 	192.168.0.1
ns2		A 	192.168.0.2

delegation	NS	ns1.delegation
		NS	ns2.delegation
ns1.delegation	A 	192.168.0.1
ns2.delegation	A 	192.168.0.2

other		NS	ns1.other
		NS	ns2.other
ns1.other	A	192.168.0.1
ns2.other	A	192.168.0.2

www		CNAME	web
web		A	192.168.0.10
		A	192.168.0.11

@		MX	1   bert
		MX	10  ernie 
		MX	100 mx.example.com

bert		A	192.168.0.20
bert		AAAA	fe80::1
ernie		A	192.168.0.2

files._smb._tcp	SRV	0 0 445 arbys
files._smb._tcp	TXT	"\000"
arbys		A	192.168.0.30
`)

	z.Attach("", db) // updates SOA
	return z
}

// origin is the containing zone name, this zone will be delegation.origin
func delegationZone(origin dns.Name) *Zone {
	name := test.NewName("delegation").Append(origin)
	z := newZone(name)
	db := z.Db("")

	test.LoadDb(db, name, `
@ 1h IN 	SOA hostmaster ns1 (
		1	; serial
		24h	; refresh
		2h	; retry
		1000h	; expire
		48h	; mininum
)

@		NS	ns1
		NS	ns2
ns1		A	192.168.0.1
ns2		A	192.168.0.2

host		A	192.168.0.20
`)

	z.Attach("", db)
	return z
}

func newServer(t testing.TB, zones *Zones) func() {
	ctx, cancel := context.WithCancel(context.Background())
	p, err := test.ListenPacketConn("ns")
	if err != nil {
		panic(err)
	}
	ps := NewServer(test.NewLog(t), dnsconn.NewPacketConn(p, "testpacket", ""), zones, nil, NoAccess)
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		err = ps.Serve(ctx)
		ps.Close()
		wg.Done()
	}()

	c, err := test.Listen("ns")
	if err != nil {
		panic(err)
	}

	wg.Add(1)
	go func() {
		for {
			a, err := c.AcceptConn()
			if err != nil {
				t.Logf("AcceptConn: %v", err)
				break
			}
			wg.Add(1)
			go func(a *test.Conn) {
				cs := NewServer(test.NewLog(t), dnsconn.NewConn(a, "test", ""), zones, nil, NoAccess)
				err := cs.Serve(ctx)
				cs.Close()
				t.Logf("Conn server exited: %v", err)
				wg.Done()
			}(a)
		}

		wg.Done()
	}()

	return func() {
		cancel()
		c.Close()
		wg.Wait()
		if errors.Is(err, context.Canceled) {
			err = nil
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestServerShutdown(t *testing.T) {
	shutdown := newServer(t, NewZones())
	shutdown()
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
	t.Logf("%v: %s", q, section)
	for _, r := range records {
		t.Log(r)
	}

	if !test.IncludedRecordSet(records, expected) {
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
	zones.Insert(delegationZone(origin), true)
	shutdown := newServer(t, zones)
	defer shutdown()

	cases := []*queryCase{
		&queryCase{
			name:   test.NewName("www").Append(origin),
			rrtype: dns.AType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
www IN CNAME web
web IN A 192.168.0.10
`),
		},
		&queryCase{
			name:   origin,
			rrtype: dns.MXType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
@ IN MX 1 bert
@ IN MX 10 ernie
`),
			additional: test.NewRecordSet(origin, `
bert IN A 192.168.0.20
ernie IN A 192.168.0.2
`),
		},
		&queryCase{
			name:   test.NewName("files._smb._tcp").Append(origin),
			rrtype: dns.SRVType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
files._smb._tcp IN SRV 0 0 445 arbys
`),
			additional: test.NewRecordSet(origin, `
arbys IN A 192.168.0.30
`),
		},
		&queryCase{
			name:   test.NewName("www").Append(origin),
			rrtype: dns.TXTType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
www in CNAME web
`),
		},
		&queryCase{
			name:   origin,
			rrtype: dns.NSType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
@ IN NS ns1
@ IN NS ns2
`),
			additional: test.NewRecordSet(origin, `
ns1 IN A 192.168.0.1
ns2 IN A 192.168.0.2
`),
		},
		&queryCase{
			name:   test.NewName("bogus").Append(origin),
			rrtype: dns.AType,
			rcode:  dns.NXDomain,
			authority: test.NewRecordSet(origin, `
@ 1h IN SOA hostmaster ns1 1 24h 2h 1000h 48h
`),
		},
		&queryCase{
			name:   test.NewName("host.other").Append(origin),
			rrtype: dns.AType,
			rcode:  dns.NoError,
			authority: test.NewRecordSet(origin, `
other IN NS ns1.other
other IN NS ns2.other
`),
			additional: test.NewRecordSet(origin, `
ns1.other IN A 192.168.0.1
ns2.other IN A 192.168.0.2
`),
		},
		&queryCase{
			name:   test.NewName("host.delegation").Append(origin),
			rrtype: dns.AType,
			rcode:  dns.NoError,
			answers: test.NewRecordSet(origin, `
host.delegation IN A 192.168.0.20
`),
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
		if resp.RA {
			t.Fatal("RA is true")
		}
		if !resp.AA {
			t.Fatal("AA is false")
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
	res.Close()
}

func TestServerZoneTransfer(t *testing.T) {
	zones := NewZones()
	origin := test.NewName("horsegrinders.com")
	primary := exampleZone(origin)
	secondary := newZone(origin)
	zones.Insert(primary, true)
	shutdown := newServer(t, zones)
	defer shutdown()

	c, err := test.Dial("xfer", "ns")
	if err != nil {
		t.Fatal(err)
	}
	res := resolver.NewResolver(nil, dnsconn.NewConn(c, "test", ""), false)

	msg := &dns.Message{
		Opcode: dns.StandardQuery,
		Questions: []dns.Question{
			dns.NewDNSQuestion(origin, dns.AXFRType, dns.INClass),
		},
	}

	msg, err = res.Transact(context.Background(), nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	records := msg.Answers

	err = secondary.Xfer(false, func() (*dns.Record, error) {
		if len(records) == 0 {
			msg, err = res.Receive(context.Background(), msg.ID)
			if err != nil {
				return nil, err
			}
			records = msg.Answers
			if len(records) == 0 {
				return nil, io.ErrUnexpectedEOF
			}
		}
		r := records[0]
		records = records[1:]
		return r, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	res.Close()

	compareZone(t, primary, secondary)
}

type updateCase struct {
	prereq []*dns.Record
	update []*dns.Record
	rcode  dns.RCode
}

func compareUpdate(t *testing.T, res *resolver.Resolver, update []*dns.Record) {
	for _, u := range update {
		t.Logf("update %v", u)
		msg := &dns.Message{
			Opcode: dns.StandardQuery,
			Questions: []dns.Question{
				dns.NewDNSQuestion(u.Name(), u.Type(), dns.INClass),
			},
		}
		msg, err := res.Transact(context.Background(), nil, msg)
		if msg == nil {
			t.Fatal(err)
		}

		if msg.RCode != dns.NoError && msg.RCode != dns.NXDomain {
			t.Fatal(msg.RCode)
		}

		switch {
		// delete all rrsets
		case u.Class() == dns.AnyClass && u.Type() == dns.AnyType:
			if msg.RCode != dns.NXDomain {
				t.Fatalf("expected %v, got %v", dns.NXDomain, msg.RCode)
			}

			// delete an rrset
		case u.Class() == dns.AnyClass && u.Type() != dns.AnyType:
			for _, r := range msg.Answers {
				if r.Type() == u.Type() {
					t.Fatalf("rrset %v should be gone, found %v", u.Type(), r)
				}
			}

			// delete an rr from an rrset
		case u.Class() == dns.NoneClass && u.Type() != dns.AnyType:
			r := &dns.Record{
				H: dns.NewHeader(u.Name(), u.Type(), dns.INClass, time.Hour),
				D: u.D,
			}
			if !test.ExcludedRecordSet(msg.Answers, []*dns.Record{r}) {
				t.Fatalf("%v should be gone", r)
			}

			// add to an rrset
		case u.Class() == dns.INClass && u.Type() != dns.AnyType:
			r := &dns.Record{
				H: dns.NewHeader(u.Name(), u.Type(), dns.INClass, time.Hour),
				D: u.D,
			}
			if !test.IncludedRecordSet(msg.Answers, []*dns.Record{r}) {
				t.Fatalf("%v should be present", r)
			}

		default:
			t.Fatalf("illegal update %v", u)
		}
	}
}

func TestServerUpdate(t *testing.T) {
	origin := test.NewName("horsegrinders.com")
	zones := NewZones()
	zones.Insert(exampleZone(origin), true)
	shutdown := newServer(t, zones)
	defer shutdown()

	cases := []*updateCase{
		&updateCase{
			prereq: test.NewRecordSet(origin, `
grover ANY ANY
`),
			update: test.NewRecordSet(origin, `
grover IN A 192.168.0.23
`),
			rcode: dns.NXDomain,
		},
		&updateCase{
			prereq: test.NewRecordSet(origin, `
ernie ANY AAAA
`),
			update: test.NewRecordSet(origin, `
ernie IN AAAA fe80::2
`),
			rcode: dns.NXRRSet,
		},
		&updateCase{
			prereq: test.NewRecordSet(origin, `
bert NONE ANY
`),
			update: test.NewRecordSet(origin, `
bert IN A 192.168.0.20
`),
			rcode: dns.YXDomain,
		},
		&updateCase{
			prereq: test.NewRecordSet(origin, `
bert NONE A
`),
			update: test.NewRecordSet(origin, `
bert IN A 192.168.0.20
`),
			rcode: dns.YXRRSet,
		},
		&updateCase{
			prereq: test.NewRecordSet(origin, `
bert IN A 192.168.0.21
`),
			update: test.NewRecordSet(origin, `
bert IN A 192.168.0.20
`),
			rcode: dns.NXRRSet,
		},
		&updateCase{
			update: test.NewRecordSet(test.NewName("tessier-ashpool.net"), `
grover IN A 192.168.0.30
`),
			rcode: dns.NotZone,
		},
		&updateCase{
			update: test.NewRecordSet(origin, `
ernie IN AAAA fe80::2
web NONE A 192.168.0.11
bert ANY A
arbys ANY ANY
`),
		},
	}

	p, err := test.DialPacketConn("client", "ns")
	if err != nil {
		t.Fatal(err)
	}
	res := resolver.NewResolver(zones, dnsconn.NewPacketConn(p, "testpacket", ""), false)

	for n, c := range cases {
		msg := &dns.Message{
			Opcode: dns.Update,
			Questions: []dns.Question{
				dns.NewDNSQuestion(origin, dns.SOAType, dns.INClass),
			},
			Answers:   c.prereq,
			Authority: c.update,
		}
		msg, err := res.Transact(context.Background(), nil, msg)
		if msg == nil {
			t.Fatal(err)
		}
		if msg.RCode != c.rcode {
			t.Fatalf("case %d: expected %v, got %v", n, c.rcode, msg.RCode)
		}
		if msg.RCode == dns.NoError {
			compareUpdate(t, res, c.update)
		}
	}

	res.Close()
}
