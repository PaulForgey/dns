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
	logger         *log.Logger
	conn           dnsconn.Conn
	zones          *Zones
	res            *resolver.Resolver
	allowRecursion Access
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
		msg, from, err := s.conn.ReadFromIf(ctx, func(*dns.Message) bool {
			return true // we are the only consumer
		})
		if err != nil {
			s.logger.Printf("listener %v exiting: %v", s.conn, err)
			return err
		}
		if msg.QR {
			continue // only questions
		}

		if len(msg.Questions) == 0 {
			// XXX this needs to change if we ever support an op with no Q section
			s.answer(dns.FormError, true, msg, from)
			continue
		}
		q := msg.Questions[0]
		// XXX if qdcount > 1, we use the first and ignore the others

		s.logger.Printf("%s:%v:%v: %v", s.conn.Interface(), from, msg.Opcode, msg.Questions[0])

		var zone *Zone

		switch msg.Opcode {
		case dns.Update, dns.Notify:
			if zone = s.zones.Zone(q.Name()); zone != nil {
				switch msg.Opcode {
				case dns.Update:
					if zone.AllowUpdate == nil || !zone.AllowUpdate.Check(from, s.conn.Interface(), "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.update(ctx, msg, from, zone)

				case dns.Notify:
					if zone.AllowNotify == nil || !zone.AllowNotify.Check(from, s.conn.Interface(), "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.notify(ctx, msg, from, zone)
				}
			}

		case dns.StandardQuery:
			switch q.Type() {
			case dns.AXFRType, dns.IXFRType:
				if zone = s.zones.Zone(q.Name()); zone != nil {
					if zone.AllowTransfer == nil || !zone.AllowTransfer.Check(from, s.conn.Interface(), "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.ixfr(ctx, msg, from, zone)
				}

			default:
				if zone, _ = s.zones.Find(q.Name()).(*Zone); zone != nil {
					if zone.AllowQuery == nil || !zone.AllowQuery.Check(from, s.conn.Interface(), "") {
						s.answer(dns.Refused, true, msg, from)
						continue
					}
					s.query(ctx, msg, from, zone)
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
	if _, ok := conn.(*dnsconn.PacketConn); ok {
		msgSize := dnsconn.MinMessageSize
		if msg.EDNS != nil {
			msgSize = int(msg.EDNS.H.(*dns.EDNSHeader).MaxMessageSize())
			if msgSize < dnsconn.MinMessageSize {
				msgSize = dnsconn.MinMessageSize
			}
			msg.EDNS = &dns.Record{
				H: dns.NewEDNSHeader(uint16(dnsconn.UDPMessageSize), 0, 0, 0),
				D: &dns.EDNSRecord{},
			}
		}
		return msgSize
	}
	return dnsconn.MaxMessageSize
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
	return s.conn.WriteTo(msg, to, msgSize)
}
