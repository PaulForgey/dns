package ns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime/trace"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var ErrNoResolver = errors.New("server has no resolver")
var ErrNoConnection = errors.New("server has no connection")
var ErrNoNS = errors.New("zone has no NS records")
var ErrNoNSAddrs = errors.New("zone has no resolvable hosts for NS records")

type Access interface {
	Check(ctx context.Context, from net.Addr, iface string, resource string) bool
}

type Server struct {
	zones  *Zones
	logger *log.Logger
	conn   dnsconn.Conn

	// unicast dns
	res            *resolver.Resolver
	allowRecursion Access

	// mDNS
	lk       sync.Mutex
	mqueries []dns.Question            // questions being asked, to batch up
	send     *time.Timer               // delay to send a batch of queries
	probing  map[string][]*dns.Message // redirect a copy of messages to names being probed
	owners   map[string]func()         // if we lose a conflict, call this owner
	host     dns.Name                  // current name of this host being announced, if any
}

type allAccess bool

func (a allAccess) Check(context.Context, net.Addr, string, string) bool {
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
		probing:        make(map[string][]*dns.Message),
		owners:         make(map[string]func()),
	}
}

// Close closes the underlying connection in the Server
func (s *Server) Close() error {
	return s.conn.Close()
}

func (s *Server) String() string {
	return s.conn.String()
}

// Serve runs a unicast server until the context is canceled.
// It is safe and possible, although not necessarily beneficial, to have multiple Serve routines on the same Server instance
// if the underlying connection is packet based.
func (s *Server) Serve(ctx context.Context) error {
	if s.conn == nil {
		return ErrNoConnection
	}
	for {
		msg, from, err := s.conn.ReadFromIf(ctx, func(msg *dns.Message) bool {
			return !msg.QR // only questions
		})
		if err != nil {
			s.logger.Printf("listener %v exiting: %v", s.conn, err)
			return err
		}

		iface := msg.Iface

		if len(msg.Questions) != 1 {
			// XXX this needs to change if we ever support an op with no Q section or multiple questions
			s.answer(
				fmt.Errorf("%w: %d questions in question section", dns.FormError, len(msg.Questions)),
				true,
				msg,
				from,
			)
			continue
		}
		q := msg.Questions[0]
		tctx, task := trace.NewTask(ctx, "query")
		category := msg.Opcode.String()
		trace.Logf(tctx, category, "msg.ID=%d %v", msg.ID, q)

		var zone *Zone

		switch msg.Opcode {
		case dns.Update, dns.Notify:
			if zone = s.zones.Zone(q.Name()); zone != nil {
				switch msg.Opcode {
				case dns.Update:
					if zone.AllowUpdate == nil || !zone.AllowUpdate.Check(tctx, from, iface, "") {
						s.answer(
							fmt.Errorf("%w: no update in %v from %v",
								dns.Refused,
								zone.Name(),
								from,
							),
							true,
							msg,
							from,
						)
						task.End()
						continue
					}
					go func() {
						defer trace.StartRegion(tctx, category).End()
						trace.Logf(tctx, category, "zone=%v", zone.Name())
						s.update(tctx, iface, msg, from, zone)
					}()

				case dns.Notify:
					if zone.AllowNotify == nil || !zone.AllowNotify.Check(tctx, from, iface, "") {
						s.answer(
							fmt.Errorf("%w: no notify in %v from %v",
								dns.Refused,
								zone.Name(),
								from,
							),
							true,
							msg,
							from,
						)
						task.End()
						continue
					}
					go func() {
						defer trace.StartRegion(tctx, category).End()
						trace.Logf(tctx, category, "zone=%v", zone.Name())
						s.notify(tctx, iface, msg, from, zone)
					}()
				}
			}

		case dns.StandardQuery:
			switch q.Type() {
			case dns.AXFRType, dns.IXFRType:
				if zone = s.zones.Zone(q.Name()); zone != nil {
					if zone.AllowTransfer == nil || !zone.AllowTransfer.Check(tctx, from, iface, "") {
						s.answer(
							fmt.Errorf(
								"%w: no transfer in %v to %v",
								dns.Refused,
								zone.Name(),
								from,
							),
							true,
							msg,
							from,
						)
						task.End()
						continue
					}
					go func() {
						defer trace.StartRegion(tctx, "xfr").End()
						trace.Logf(tctx, "xfr", "zone=%v", zone.Name())
						s.ixfr(tctx, msg, from, zone)
					}()
				}

			default:
				if zone, _ = s.zones.Find(q.Name()).(*Zone); zone != nil {
					if zone.AllowQuery == nil || !zone.AllowQuery.Check(tctx, from, iface, "") {
						s.answer(
							fmt.Errorf(
								"%w: no query in %v from %v",
								dns.Refused,
								zone.Name(),
								from,
							),
							true,
							msg,
							from,
						)
						task.End()
						continue
					}
					go func() {
						defer trace.StartRegion(tctx, category).End()
						trace.Logf(tctx, category, "zone=%v", zone.Name())
						s.query(tctx, msg, from, zone)
					}()
				}
			}

		default:
			s.answer(fmt.Errorf("%w: opcode=%d", dns.NotImplemented, msg.Opcode), true, msg, from)
			task.End()
			continue
		}

		if zone == nil {
			s.answer(fmt.Errorf("%w: nil zone for %v", dns.Refused, q.Name()), true, msg, from)
		}
		task.End()
	}
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

			mySize := dnsconn.UDPMessageSize
			if mc, ok := conn.(*dnsconn.Multicast); ok {
				mySize = mc.MessageSize()
			}

			msg.EDNS = dns.NewEDNS(uint16(mySize), 0, 0, 0)
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
		}
		var q dns.Question
		if len(msg.Questions) > 0 {
			q = msg.Questions[0]
		}
		s.logger.Printf("responding to %v: %v %v", to, q, err)
	}

	if clear {
		msg.Answers = nil
		msg.Authority = nil
		msg.Additional = nil
	}

	msgSize := messageSize(s.conn, msg)
	return s.conn.WriteTo(msg, to, msgSize)
}
