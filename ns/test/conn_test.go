package test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
)

func newName(s string) dns.Name {
	n, err := dns.NameWithString(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestConn(t *testing.T) {
	l, err := Listen("ep2")
	if err != nil {
		t.Fatal(err)
	}

	var s2 *Conn
	errch := make(chan error, 1)

	go func() {
		var err2 error
		s2, err2 = l.AcceptConn()
		errch <- err2
	}()

	s1, err := Dial("ep1", "ep2")

	if err != nil {
		t.Fatal(err)
	}

	err = <-errch
	if err != nil {
		t.Fatal(err)
	}

	l.Close()

	c1, c2 := dnsconn.NewConn(s1, "test", ""), dnsconn.NewConn(s2, "test", "")

	if !c1.VC() || !c2.VC() {
		t.Fatal("VC() should be true")
	}

	testPair(t, c1, c2)

	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = s2.Read(nil)
	if !errors.Is(err, dnsconn.ErrClosed) {
		t.Fatalf("%v is not %v", err, dnsconn.ErrClosed)
	}
	if err := c2.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketConn(t *testing.T) {
	p2, err := ListenPacketConn("ep2")
	if err != nil {
		t.Fatal(err)
	}
	p1, err := DialPacketConn("ep1", "ep2")
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := dnsconn.NewConn(p1, "test", ""), dnsconn.NewConn(p2, "test", "")

	if c1.VC() || c2.VC() {
		t.Fatal("VC() should be false")
	}

	testPair(t, c1, c2)
	c1.Close()
	c2.Close()
}

func TestStream(t *testing.T) {
	s1, s2 := NewConn("ep1", "ep2")
	c1, c2 := dnsconn.NewConn(s1, "test", ""), dnsconn.NewConn(s2, "test", "")
	testPair(t, c1, c2)
	c1.Close()
	c2.Close()
}

func testPair(t *testing.T, c1, c2 dnsconn.Conn) {
	msg1 := &dns.Message{
		ID:     1234,
		Opcode: dns.Update,
		RD:     true,
		Questions: []dns.Question{
			dns.NewDNSQuestion(newName("name.domain.com"), dns.AType, dns.INClass),
		},
		Additional: []*dns.Record{
			&dns.Record{
				H: dns.NewHeader(newName("host1.domain.com"), dns.AType, dns.INClass, time.Hour),
				D: &dns.ARecord{Address: [4]byte{1, 2, 3, 4}},
			},
			&dns.Record{
				H: dns.NewHeader(newName("host2.domain.com"), dns.AType, dns.INClass, time.Hour),
				D: &dns.ARecord{Address: [4]byte{4, 3, 2, 1}},
			},
		},
	}

	err := c1.WriteTo(msg1, nil, dnsconn.MaxMessageSize)
	if err != nil {
		t.Fatal(err)
	}

	msg2, from, err := c2.ReadFromIf(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	switch from.Network() {
	case "test", "testpacket":
		if from.String() != "ep1" {
			t.Fatalf("peer name '%s', expected 'ep1'", from.String())
		}
	default:
		t.Fatalf("from addr unexpected network %s", from.Network())
	}

	output1 := &strings.Builder{}
	output2 := &strings.Builder{}
	codec1 := dns.NewTextWriter(output1)
	codec2 := dns.NewTextWriter(output2)

	if err := codec1.Encode(msg1); err != nil {
		t.Fatal(err)
	}
	if err := codec2.Encode(msg2); err != nil {
		t.Fatal(err)
	}

	if output1.String() != output2.String() {
		t.Fatalf("\n%v\n%v", output1, output2)
	}
}
