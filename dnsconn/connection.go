package dnsconn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"tessier-ashpool.net/dns"
)

const (
	MaxMessageSize = 65535 // 16 bit size field
	MinMessageSize = 512   // bsd BUFSIZ used in ancient times
)

const (
	MaxBacklog = 20 // maximum number of unclaimed messages over packet connections
)

var UDPMessageSize = 8192 // preferred message size. may be changed at runtime

var ErrClosed = errors.New("closed")
var ErrNotConn = errors.New("not connected")
var ErrIsConn = errors.New("connected")
var ErrUnknownInterface = errors.New("unknown interface")

var maxBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}
var bufferPool = sync.Pool{}

var ifindexes = sync.Map{} // XXX assumes stability of interface indexes
var ifnames = sync.Map{}

type message struct {
	msg        *dns.Message
	iface      string
	source     net.Addr
	next, prev *message
}

func (m *message) insertTail(n *message) {
	// insert n before m
	n.next = m
	n.prev = m.prev
	n.next.prev = n
	n.prev.next = n
}

func (m *message) remove() {
	m.prev.next = m.next
	m.next.prev = m.prev
}

func (m *message) empty() bool {
	return m.next == m
}

// The Conn type sends and receives *dns.Message instances
type Conn interface {
	fmt.Stringer

	// Network returns the network name the connection was created with
	Network() string

	// WriteTo sends a dns message to addr limited to msgSize. If the connection is stream oriented, addr must be nil.
	// If the connection is packet oriented, msg may be nil if the connection has an idea of a default destination.
	WriteTo(msg *dns.Message, iface string, addr net.Addr, msgSize int) error

	// ReadFromIf receives a dns message. If the connection is stream oriented, the from address will be nil.
	// If match is nil, any message is returned. If a message is filtered out of a stream connection, that message
	// will be lost. Messages filtered out of stream connections are presented to future callers.
	ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (msg *dns.Message, iface string, from net.Addr, err error)

	// Close closes the underyling connection and allows any blocking ReadFromIf or WriteTo operations to immediately
	// fail.
	Close() error

	// VC returns true if the underlying transport is stream oriented
	VC() bool
}

type conn struct {
	network string
	iface   string
	xid     uint32
	pool    *sync.Pool
}

// the PacketConn type is a packet oriented Connection
type PacketConn struct {
	*conn
	c        net.PacketConn
	p4       *ipv4.PacketConn
	p6       *ipv6.PacketConn
	lk       *sync.Mutex
	cond     *sync.Cond
	messages *message
	backlog  int
	err      error
	mdns     bool
}

// the StreamConn type is a stream oriented Connection
type StreamConn struct {
	*conn
	c net.Conn
}

func ifname(ifindex int) string {
	entry, ok := ifindexes.Load(ifindex)
	if !ok {
		ifi, err := net.InterfaceByIndex(ifindex)
		if err != nil || ifi == nil {
			return ""
		}
		ifindexes.Store(ifindex, ifi.Name)
		return ifi.Name
	}
	return entry.(string)
}

func ifbyname(iface string) int {
	entry, ok := ifnames.Load(iface)
	if !ok {
		ifi, err := net.InterfaceByName(iface)
		if err != nil || ifi == nil {
			return 0
		}
		ifnames.Store(iface, ifi.Index)
		return ifi.Index
	}
	return entry.(int)
}

// NewConnection creates a new Conn instance with a net.Conn or net.PacketConn
func NewConn(conn net.Conn, network, iface string) Conn {
	if p, ok := conn.(net.PacketConn); ok {
		return NewPacketConn(p, network, iface)
	} else {
		return NewStreamConn(conn, network, iface)
	}
}

// Network returns the network this connection was created with
func (c *conn) Network() string {
	return c.network
}

// NewPacketConn creates a packet oriented connection from a net.PacketConn
func NewPacketConn(c net.PacketConn, network, iface string) *PacketConn {
	// sentinal node
	messages := &message{}
	messages.next = messages
	messages.prev = messages

	lk := &sync.Mutex{}
	p := &PacketConn{
		conn: &conn{
			network: network,
			iface:   iface,
			pool:    &bufferPool,
		},
		c:        c,
		lk:       lk,
		cond:     sync.NewCond(lk),
		messages: messages,
	}

	switch network {
	case "udp", "udp6":
		p.p6 = ipv6.NewPacketConn(c)
		p.p6.SetControlMessage(ipv6.FlagInterface, true)
	case "udp4":
		p.p4 = ipv4.NewPacketConn(c)
		p.p4.SetControlMessage(ipv4.FlagInterface, true)
	}

	var port int
	if u, ok := c.LocalAddr().(*net.UDPAddr); ok {
		port = u.Port
	}

	go func(p *PacketConn) {
		var msg *dns.Message
		var source net.Addr
		var err error

		for err == nil {
			msg, iface, source, err = p.readFrom()
			if source != nil && port != 0 {
				if u, ok := source.(*net.UDPAddr); ok {
					if u.Port != port {
						msg.ClientPort = true
					}
				}
			}

			p.lk.Lock()
			// XXX ignore malformed message, although there should be a way for the server
			//     to answer with FormError if it wants
			if err != nil && msg == nil {
				p.err = err // connection error
			} else if err == nil {
				p.messages.insertTail(&message{msg: msg, iface: iface, source: source})
				p.backlog++
			} else {
				err = nil
				p.lk.Unlock()
				continue
			}

			if p.backlog == MaxBacklog {
				p.messages.next.remove()
				p.backlog--
			}

			p.cond.Broadcast()
			p.lk.Unlock()
		}
	}(p)

	return p
}

// MDNS sets MDNS specific wire decoding
func (p *PacketConn) MDNS(pool *sync.Pool) {
	p.mdns = true
	p.conn.pool = pool
}

// VC always returns false as a PacketConn is never stream oriented
func (p *PacketConn) VC() bool {
	return false
}

func (p *PacketConn) String() string {
	return p.c.LocalAddr().String()
}

// WriteTo sends a *dns.Message. If the message could not fit but could stil be validly sent with reduced extra records,
// Write returns nil but will update msg with what it actually sent.
// msgSize is the maximum message size to fit the message.
func (p *PacketConn) WriteTo(msg *dns.Message, iface string, addr net.Addr, msgSize int) error {
	var msgBuf []byte

	if msgSize < MinMessageSize || msgSize > MaxMessageSize {
		panic("rediculous msgSize")
	}

	buffer, _ := p.conn.pool.Get().([]byte)
	if len(buffer) < msgSize {
		// be opportunistic sending, but do not put every random crazy ass size back in the pool
		buffer = make([]byte, msgSize)
	} else {
		defer p.conn.pool.Put(buffer)
	}

	msgBuf = buffer[:msgSize]

	if !msg.QR && msg.ID == 0 {
		msg.ID = uint16(atomic.AddUint32(&p.conn.xid, 1))
	}

	writer := dns.NewWireCodec(msgBuf)
	err := writer.Encode(msg)
	var truncated *dns.Truncated
	if !msg.NoTC && errors.As(err, &truncated) {
		switch truncated.Section {
		case 0:
			return err // can't fit the question!
		case 1:
			if !(p.mdns && msg.QR) {
				msg.TC = true
			}
			msg.Answers = msg.Answers[:truncated.At]
			if len(msg.Answers) == 0 {
				return err // no room to answer at all
			}
		case 2:
			// not great, not terrible
			msg.Authority = msg.Authority[:truncated.At]
			if len(msg.Authority) == 0 {
				return err // must be at least one if we are answering with an authority section
			}
		case 3:
			// shed optional records
			msg.Additional = msg.Additional[:truncated.At]
		}
		writer.Reset(msgBuf)
		err = writer.Encode(msg)
	}
	if err != nil {
		return err
	}

	msgBuf = msgBuf[:writer.Offset()]
	if addr != nil {
		if iface != "" {
			switch {
			case p.p6 != nil:
				ifindex := ifbyname(iface)
				if ifindex == 0 {
					return ErrUnknownInterface
				}
				_, err = p.p6.WriteTo(msgBuf, &ipv6.ControlMessage{IfIndex: ifindex}, addr)

			case p.p4 != nil:
				ifindex := ifbyname(iface)
				if ifindex == 0 {
					return ErrUnknownInterface
				}
				_, err = p.p4.WriteTo(msgBuf, &ipv4.ControlMessage{IfIndex: ifindex}, addr)

			default:
				_, err = p.c.WriteTo(msgBuf, addr)

			}
		} else {
			_, err = p.c.WriteTo(msgBuf, addr)
		}
	} else {
		c, ok := p.c.(net.Conn)
		if !ok {
			return ErrNotConn
		}
		_, err = c.Write(msgBuf)
	}

	return err
}

// ReadFromIf receives a *dns.Message, returning the message and, if unconnected, the source address.
// match should be quick. The connection is locked during its call.
func (p *PacketConn) ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, string, net.Addr, error) {
	var err error

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			p.lk.Lock()
			p.cond.Broadcast()
			p.lk.Unlock()
		case <-done:
		}
	}()

	p.lk.Lock()
	for err == nil {
		// first check unclaimed baggage
		for m := p.messages.next; m != p.messages; m = m.next {
			if match == nil || match(m.msg) {
				m.remove()
				p.backlog--
				p.lk.Unlock()

				return m.msg, m.iface, m.source, nil
			}
		}

		err = ctx.Err()
		if err == nil {
			err = p.err
		}
		if err != nil {
			break
		}

		p.cond.Wait()
	}
	p.lk.Unlock()

	return nil, "", nil, err
}

func (p *PacketConn) readFrom() (*dns.Message, string, net.Addr, error) {
	var msgBuf []byte
	var from net.Addr
	var err error

	buffer, _ := p.conn.pool.Get().([]byte)
	if len(buffer) < UDPMessageSize {
		// no buffer or drop shorter buffer, always put appropriate buffer back in
		buffer = make([]byte, UDPMessageSize)
	}
	defer p.conn.pool.Put(buffer)

	var r int
	iface := p.conn.iface

	switch {
	case p.p6 != nil:
		var cm6 *ipv6.ControlMessage
		r, cm6, from, err = p.p6.ReadFrom(buffer)
		if cm6 != nil && cm6.IfIndex > 0 {
			iface = ifname(cm6.IfIndex)
		}

	case p.p4 != nil:
		var cm4 *ipv4.ControlMessage
		r, cm4, from, err = p.p4.ReadFrom(buffer)
		if cm4 != nil && cm4.IfIndex > 0 {
			iface = ifname(cm4.IfIndex)
		}

	default:
		r, from, err = p.c.ReadFrom(buffer)
	}

	if err != nil {
		return nil, "", nil, err
	}
	msgBuf = buffer[:r]

	reader := dns.NewWireCodec(msgBuf)
	if p.mdns {
		reader.MDNS()
	}
	msg := &dns.Message{}
	err = reader.Decode(msg)
	return msg, iface, from, err
}

// Close closes the underlying conn
func (p *PacketConn) Close() error {
	return p.c.Close()
}

// NewStreamConn creates a stream oriented connection from a net.Conn
func NewStreamConn(c net.Conn, network, iface string) *StreamConn {
	s := &StreamConn{
		conn: &conn{
			network: network,
			iface:   iface,
			pool:    &maxBufferPool,
		},
		c: c,
	}

	return s
}

func (s *StreamConn) String() string {
	return s.c.LocalAddr().String()
}

// VC returns true if the underlying connection is stream oriented. (A StreamConn may use a connected net.PacketConn)
func (s *StreamConn) VC() bool {
	_, ok := s.c.(net.PacketConn)
	return !ok
}

// addr must be nil. msgSize should be MaxMessageSize
func (s *StreamConn) WriteTo(msg *dns.Message, iface string, addr net.Addr, msgSize int) error {
	var msgBuf []byte

	if msgSize < MinMessageSize || msgSize > MaxMessageSize {
		panic("rediculous msgSize")
	}
	if addr != nil {
		return ErrIsConn
	}

	buffer := s.conn.pool.Get().([]byte)
	defer s.conn.pool.Put(buffer)

	msgBuf = buffer[:msgSize]

	if !msg.QR && msg.ID == 0 {
		msg.ID = uint16(atomic.AddUint32(&s.conn.xid, 1))
	}

	writer := dns.NewWireCodec(msgBuf)
	err := writer.Encode(msg)
	if err != nil {
		return err
	}

	var hdr [2]byte
	msgBuf = msgBuf[:writer.Offset()]
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msgBuf)))

	s.c.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	if _, ok := s.c.(net.PacketConn); !ok {
		if _, err := s.c.Write(hdr[:]); err != nil {
			return err
		}
	}
	if _, err := s.c.Write(msgBuf); err != nil {
		return err
	}

	return nil
}

func (s *StreamConn) ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, string, net.Addr, error) {
	var msgBuf []byte
	var hdr [2]byte
	var err error

	buffer := s.conn.pool.Get().([]byte)
	defer s.conn.pool.Put(buffer)

	for {
		s.c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		if pc, ok := s.c.(net.PacketConn); ok {
			length, _, err := pc.ReadFrom(buffer)
			if err != nil {
				return nil, "", nil, err
			}
			msgBuf = buffer[:length]
		} else {
			if _, err = io.ReadFull(s.c, hdr[:]); err != nil {
				return nil, "", nil, err
			}
			length := int(binary.BigEndian.Uint16(hdr[:]))
			if length > len(buffer) {
				// we create buffers of a size which fit 16 bit lengths..
				panic("short buffer put back in pool?")
			}
			msgBuf = buffer[:length]
			if _, err = io.ReadFull(s.c, msgBuf); err != nil {
				return nil, "", nil, err
			}
		}

		reader := dns.NewWireCodec(msgBuf)
		msg := &dns.Message{}
		err = reader.Decode(msg)

		if err != nil || match == nil || match(msg) {
			return msg, s.iface, nil, err
		}
	}
}

func (s *StreamConn) Close() error {
	return s.c.Close()
}
