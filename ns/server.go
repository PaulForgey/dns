package ns

import (
	"context"
	"errors"
	"log"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var ErrNoResolver = errors.New("server has no resolver")
var ErrNoConnection = errors.New("server has no connection")
var ErrNoNS = errors.New("zone has no NS records")
var ErrNoNSAddrs = errors.New("zone has no resolvable hosts for NS records")

type Access interface {
	Check(from net.Addr, iface string, resource string) bool
}

type Server struct {
	zones  *Zones
	logger *log.Logger
	conn   dnsconn.Conn

	// unicast dns
	res            *resolver.Resolver
	allowRecursion Access

	// mDNS
}

type allAccess bool

func (a allAccess) Check(net.Addr, string, string) bool {
	return bool(a)
}

// AllAccess is an instance of the Access interface which always grants access
var AllAccess = allAccess(true)

// NoAccess is an instance of the Access interface which always denies access
var NoAccess = allAccess(false)

// NewServer creates a server instance
func NewServer(
	logger *log.Logger,
	conn dnsconn.Conn,
	zones *Zones,
	res *resolver.Resolver,
	allowRecursion Access,
) *Server {
	return &Server{
		logger:         logger,
		conn:           conn,
		zones:          zones,
		res:            res,
		allowRecursion: allowRecursion,
	}
}

// Serve runs a unicast server until the context is canceled.
// It is safe and possible, although not necessarily beneficial, to have multiple Serve routines on the same Server instance
// if the underlying connection is packet based.
func (s *Server) Serve(ctx context.Context) error {
	if s.conn == nil {
		return ErrNoConnection
	}
	for {
		msg, iface, from, err := s.conn.ReadFromIf(ctx, func(msg *dns.Message) bool {
			return !msg.QR // only questions
		})
		if err != nil {
			s.logger.Printf("listener %v exiting: %v", s.conn, err)
			return err
		}

		if len(msg.Questions) != 1 {
			// XXX this needs to change if we ever support an op with no Q section or multiple questions
			s.answer(dns.FormError, true, msg, from)
			continue
		}
		q := msg.Questions[0]

		s.logger.Printf("%s:%v:%v: %v", iface, from, msg.Opcode, msg.Questions[0])

		var zone *Zone

		switch msg.Opcode {
		case dns.Update, dns.Notify:
			if zone = s.zones.Zone(q.Name()); zone != nil {
				switch msg.Opcode {
				case dns.Update:
					if zone.AllowUpdate == nil || !zone.AllowUpdate.Check(from, iface, "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.update(ctx, iface, msg, from, zone)

				case dns.Notify:
					if zone.AllowNotify == nil || !zone.AllowNotify.Check(from, iface, "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.notify(ctx, iface, msg, from, zone)
				}
			}

		case dns.StandardQuery:
			switch q.Type() {
			case dns.AXFRType, dns.IXFRType:
				if zone = s.zones.Zone(q.Name()); zone != nil {
					if zone.AllowTransfer == nil || !zone.AllowTransfer.Check(from, iface, "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					go s.ixfr(ctx, msg, from, zone)
				}

			default:
				if zone, _ = s.zones.Find(q.Name()).(*Zone); zone != nil {
					if zone.AllowQuery == nil || !zone.AllowQuery.Check(from, iface, "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					go s.query(ctx, msg, iface, from, zone)
				}
			}

		default:
			s.answer(dns.NotImplemented, true, msg, from)
			continue
		}

		if zone == nil {
			s.answer(dns.Refused, true, msg, from)
		}
	}

	return nil // unreached
}

func messageSize(conn dnsconn.Conn, msg *dns.Message) int {
	msgSize := dnsconn.MinMessageSize
	if conn.VC() {
		msgSize = dnsconn.MaxMessageSize
	} else {
		if msg.EDNS != nil {
			msgSize = int(msg.EDNS.MaxMessageSize())
			if msgSize < dnsconn.MinMessageSize {
				msgSize = dnsconn.MinMessageSize
			}
			msg.EDNS = dns.NewEDNS(uint16(dnsconn.UDPMessageSize), 0, 0, 0)
		}
	}
	return msgSize
}

func (s *Server) answer(err error, clear bool, msg *dns.Message, to net.Addr) error {
	msg.QR = true

	msg.RCode = dns.NoError
	if err != nil {
		if !errors.As(err, &msg.RCode) {
			msg.RCode = dns.ServerFailure
			s.logger.Printf("responding to %v: %v", to, err)
		}
	}

	if clear {
		msg.Answers = nil
		msg.Authority = nil
		msg.Additional = nil
	}

	msgSize := messageSize(s.conn, msg)
	return s.conn.WriteTo(msg, "", to, msgSize)
}
