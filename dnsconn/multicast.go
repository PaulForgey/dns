package dnsconn

import (
	"errors"
	"net"

	"tessier-ashpool.net/dns"
)

// The Multicast type is a specialization of a Connection type handling multicast mdns messages
type Multicast struct {
	*Connection
	gaddr   *net.UDPAddr
	msgSize int
}

// Attempt to create a listener on an unknown or ambiguous network
var ErrBadNetwork = errors.New("bad network name")

// NewMulticast returns a Connection joined to the mdns multicast group
func NewMulticast(network string, ifi *net.Interface) (*Multicast, error) {
	var msgSize int

	gaddr := &net.UDPAddr{Port: 5353}

	// multicast groups and message sizes from RFC-6762
	switch network {
	case "udp6":
		gaddr.IP = net.ParseIP("FF02::FB")
		msgSize = 9000 - 40
	case "udp4":
		gaddr.IP = net.IPv4(224, 0, 0, 251)
		msgSize = 9000 - 20
	default:
		return nil, ErrBadNetwork
	}

	conn, err := net.ListenMulticastUDP(network, ifi, gaddr)
	if err != nil {
		return nil, err
	}
	return &Multicast{
		Connection: NewConnection(conn, network),
		gaddr:      gaddr,
		msgSize:    msgSize,
	}, nil
}

func (m *Multicast) WriteTo(msg *dns.Message, addr net.Addr, _ int) error {
	if addr == nil {
		addr = m.gaddr
	}
	for {
		answers := msg.Answers

		if err := m.Connection.WriteTo(msg, addr, m.msgSize); err != nil {
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
