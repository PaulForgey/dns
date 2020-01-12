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
var ErrNoSOA = errors.New("zone has no SOA")
var ErrNoNS = errors.New("zone has no NS records")
var ErrNoNSAddrs = errors.New("zone has no resolvable hosts for NS records")

type Server struct {
	logger *log.Logger
	conn   *dnsconn.Connection
	zones  *Zones
	res    *resolver.Resolver
}

// NewServer creates a server instance
func NewServer(logger *log.Logger, conn *dnsconn.Connection, zones *Zones, res *resolver.Resolver) *Server {
	return &Server{
		logger: logger,
		conn:   conn,
		zones:  zones,
		res:    res,
	}
}

// Serve runs a unicast server answering queries for the zone set until the context is canceled or an error occurs on the conn
// It is safe and possible, although not necessarily beneficial, to have multiple Serve routines on the same Server instance
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

		var q *dns.Question
		if len(msg.Questions) > 0 {
			q = msg.Questions[0]
		} else {
			// XXX this needs to change if we ever support an op with no Q section
			answer(s.conn, dns.FormError, true, msg, from)
			continue
		}

		s.logger.Printf("%s:%v:%v: %v", s.conn.Interface, from, msg.Opcode, q)

		var zone *Zone

		switch msg.Opcode {
		case dns.Update, dns.Notify:
			if zone = s.zones.Zone(q.QName); zone != nil {
				switch msg.Opcode {
				case dns.Update:
					// XXX access control for update
					s.update(ctx, msg, from, zone)

				case dns.Notify:
					// XXX access control for notify
					s.notify(ctx, msg, from, zone)
				}
			}

		case dns.StandardQuery:
			switch q.QType {
			case dns.AXFRType, dns.IXFRType:
				if zone = s.zones.Zone(q.QName); zone != nil {
					// XXX access control for zone transfers
					s.ixfr(ctx, msg, from, zone)
				}

			default:
				if zone, _ = s.zones.Find(q.QName).(*Zone); zone != nil {
					// XXX access control for queries
					s.query(ctx, msg, from, zone)
				}
			}

		default:
			answer(s.conn, dns.NotImplemented, true, msg, from)
			continue
		}

		if zone == nil {
			answer(s.conn, dns.Refused, true, msg, from)
		}
	}

	return nil // unreached
}

func answer(conn *dnsconn.Connection, err error, clear bool, msg *dns.Message, to net.Addr) error {
	msg.QR = true

	msg.RCode = dns.NoError
	if err != nil {
		if !errors.As(err, &msg.RCode) {
			msg.RCode = dns.ServerFailure
		}
	}

	if clear {
		msg.Answers = nil
		msg.Authority = nil
		msg.Additional = nil
	}

	msgSize := dnsconn.MinMessageSize

	// client's EDNS message
	if conn.UDP {
		if msg.EDNS != nil {
			msgSize = int(msg.EDNS.RecordHeader.MaxMessageSize)
			if msgSize < dnsconn.MinMessageSize {
				msgSize = dnsconn.MinMessageSize
			}

			// respond with our own
			msg.EDNS = &dns.Record{
				RecordHeader: dns.RecordHeader{
					MaxMessageSize: dnsconn.UDPMessageSize,
					Version:        0,
				},
				RecordData: &dns.EDNSRecord{},
			}
		}
	} else {
		msgSize = dnsconn.MaxMessageSize
	}

	return conn.WriteTo(msg, to, msgSize)
}
