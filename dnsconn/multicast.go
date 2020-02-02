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

var mdnsPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 9000)
	},
}

// NewMulticast returns a Connection joined to the mdns multicast group
func NewMulticast(network, address, iface string) (*Multicast, error) {
	var conn *net.UDPConn
	var err error

	m := &Multicast{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	m.gaddr, err = net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	conn, err = net.ListenUDP(network, m.gaddr)
	if err != nil {
		return nil, err
	}

	for _, ifi := range ifaces {
		if ifi.Flags&(net.FlagUp|net.FlagMulticast) != net.FlagUp|net.FlagMulticast {
			continue
		}
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface != "" && ifi.Name != iface {
			continue
		}

		v4, v6 := false, false
		addrs, err := ifi.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() == nil {
				v6 = true
			} else {
				v4 = true
			}
			if v4 && v6 {
				break
			}
		}

		// multicast groups and message sizes from RFC-6762
		switch network {
		case "udp6":
			if v6 {
				gaddr := &net.UDPAddr{
					IP: net.ParseIP("FF02::FB"),
				}
				m.gaddr.IP = gaddr.IP
				m.msgSize = 9000 - ipv6.HeaderLen

				p := ipv6.NewPacketConn(conn)
				if err := p.JoinGroup(&ifi, gaddr); err != nil {
					p.Close()
					return nil, err
				}
				p.SetHopLimit(1)
			}

		case "udp4":
			if v4 {
				gaddr := &net.UDPAddr{
					IP: net.IPv4(224, 0, 0, 251),
				}
				m.gaddr.IP = gaddr.IP
				m.msgSize = 9000 - ipv4.HeaderLen

				p := ipv4.NewPacketConn(conn)
				if err := p.JoinGroup(&ifi, gaddr); err != nil {
					p.Close()
					return nil, err
				}
				p.SetMulticastTTL(1)
			}

		default:
			return nil, fmt.Errorf("%s: %w", network, ErrBadNetwork)
		}
	}

	m.PacketConn = NewPacketConn(conn, network, "")
	m.PacketConn.MDNS(&mdnsPool)

	return m, nil
}

func (m *Multicast) WriteTo(msg *dns.Message, iface string, addr net.Addr, msgSize int) error {
	if addr == nil {
		addr = m.gaddr
	}

	msg.TC = false
	if msg.ID == 0 {
		msgSize = m.msgSize
	}

	for {
		answers := msg.Answers

		if err := m.PacketConn.WriteTo(msg, iface, addr, msgSize); err != nil {
			return err
		}

		if !msg.TC || msg.ID != 0 {
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
