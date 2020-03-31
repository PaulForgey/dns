package ns

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns/test"
	"tessier-ashpool.net/dns/nsdb"
	"tessier-ashpool.net/dns/resolver"
)

const bigSize = 50000

func bigZone(origin dns.Name) *Zone {
	z := newZone(origin)
	db := z.Db("")

	for i := 0; i < bigSize; i++ {
		name := test.NewName(fmt.Sprintf("host%d", i)).Append(origin)
		rrmap := nsdb.NewRRMap()
		rrmap.Enter(dns.AType, dns.INClass, &nsdb.RRSet{
			Records: []*dns.Record{
				&dns.Record{
					H: dns.NewHeader(name, dns.AType, dns.INClass, time.Hour),
					D: &dns.ARecord{Address: [4]byte{192, 168, byte(i >> 8), byte(i & 0xff)}},
				},
			},
		})
		rrmap.Enter(dns.AAAAType, dns.INClass, &nsdb.RRSet{
			Records: []*dns.Record{
				&dns.Record{
					H: dns.NewHeader(name, dns.AAAAType, dns.INClass, time.Hour),
					D: &dns.AAAARecord{Address: [16]byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, byte(i >> 8), byte(i & 0xff)}},
				},
			},
		})

		err := db.Enter(name, rrmap)
		if err != nil {
			panic(err)
		}
	}

	return z
}

func BenchmarkBigZone(b *testing.B) {
	origin := test.NewName("example.com")
	z := bigZone(origin)
	zones := NewZones()
	zones.Insert(z, true)
	shutdown := newServer(b, zones)
	defer shutdown()

	p, err := test.DialPacketConn("client", "ns")
	if err != nil {
		b.Fatal(err)
	}
	res := resolver.NewResolver(nil, dnsconn.NewPacketConn(p, "testpacket", ""), false)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := rand.Int() % bigSize
			name := test.NewName(fmt.Sprintf("host%d", n)).Append(origin)
			msg := &dns.Message{
				Opcode: dns.StandardQuery,
				Questions: []dns.Question{
					dns.NewDNSQuestion(name, dns.AType, dns.INClass),
				},
			}
			msg, err := res.Transact(context.Background(), nil, msg)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	res.Close()
}
