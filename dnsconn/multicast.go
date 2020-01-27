package dnsconn

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"tessier-ashpool.net/dns"
)

// The Multicast type is a specialization of a Connection type handling multicast mdns messages
type Multicast struct {
	*PacketConn
	gaddr   *net.UDPAddr
	msgSize int
}

// Attempt to create a listener on an unknown or ambiguous network
var ErrBadNetwork = errors.New("bad network name")
var ErrBadAddress = errors.New("not parsable IP address")

var mdnsPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 9000)
	},
}

// NewMulticast returns a Connection joined to the mdns multicast group
func NewMulticast(network, address string, ifi *net.Interface) (*Multicast, error) {
	var conn *net.UDPConn
	var msgSize int
	var err error

	gaddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	gaddr.Zone = ifi.Name

	// multicast groups and message sizes from RFC-6762
	switch network {
	case "udp6":
		conn, err = net.ListenUDP(network, gaddr)
		if err != nil {
			return nil, err
		}
		gaddr.IP = net.ParseIP("FF02::FB")
		msgSize = 9000 - ipv6.HeaderLen
		p := ipv6.NewPacketConn(conn)
		if err := p.JoinGroup(ifi, gaddr); err != nil {
			p.Close()
			return nil, err
		}
		p.SetHopLimit(1)

	case "udp4":
		conn, err = net.ListenUDP(network, gaddr)
		if err != nil {
			return nil, err
		}
		gaddr.IP = net.IPv4(224, 0, 0, 251)
		msgSize = 9000 - ipv4.HeaderLen
		p := ipv4.NewPacketConn(conn)
		if err := p.JoinGroup(ifi, gaddr); err != nil {
			p.Close()
			return nil, err
		}
		p.SetMulticastTTL(1)

	default:
		return nil, fmt.Errorf("%s: %w", network, ErrBadNetwork)
	}

	p := NewPacketConn(conn, network, ifi.Name)
	p.MDNS(&mdnsPool)

	return &Multicast{
		PacketConn: p,
		gaddr:      gaddr,
		msgSize:    msgSize,
	}, nil
}

func (m *Multicast) WriteTo(msg *dns.Message, addr net.Addr, _ int) error {
	if addr == nil {
		addr = m.gaddr
	}

	msg.TC = false

	for {
		answers := msg.Answers

		if err := m.PacketConn.WriteTo(msg, addr, m.msgSize); err != nil {
			return err
		}

		if !msg.TC {
			break
		}

		// continuation: empty the question section and send remainder of answers, repeat until done
		msg.TC = false
		msg.Answers = answers[len(msg.Answers):] // pick up from first one we could not send

		msg.Questions = nil
		msg.Authority = nil
		msg.Additional = nil
	}

	return nil
}
