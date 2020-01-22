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

	"tessier-ashpool.net/dns"
)

const (
	MaxMessageSize = 65535 // 16 bit size field
	UDPMessageSize = 8192  // peferred message size
	MinMessageSize = 512   // bsd BUFSIZ used in ancient times
)

var ErrClosed = errors.New("closed")
var ErrNotConn = errors.New("not connected")

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, MaxMessageSize+2)
	},
}

type message struct {
	msg        *dns.Message
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

	// Interface returns the interface name the connection was created with
	Interface() string

	// WriteTo sends a dns message to addr limited to msgSize. If the connection is stream oriented, addr must be nil.
	// If the connection is packet oriented, msg may be nil if the connection has an idea of a default destination.
	WriteTo(msg *dns.Message, addr net.Addr, msgSize int) error

	// ReadFromIf receives a dns message. If the connection is stream oriented, the from address will be nil.
	// If match is nil, any message is returned. If a message is filtered out of a stream connection, that message
	// will be lost. Messages filtered out of stream connections are presented to future callers.
	ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, net.Addr, error)

	// Close closes the underyling connection and allows any blocking ReadFromIf or WriteTo operations to immediately
	// fail.
	Close() error
}

type conn struct {
	network string
	iface   string
	xid     uint32
}

// the PacketConn type is a packet oriented Connection
type PacketConn struct {
	*conn
	c        net.PacketConn
	lk       *sync.Mutex
	messages *message
	msgChan  chan struct{}
	err      error
}

// the StreamConn type is a stream oriented Connection
type StreamConn struct {
	*conn
	c net.Conn
}

// NewPacketConn creates a packet oriented connection from a net.PacketConn
func NewPacketConn(c net.PacketConn, network, iface string) *PacketConn {
	// sentinal node
	messages := &message{}
	messages.next = messages
	messages.prev = messages

	p := &PacketConn{
		conn: &conn{
			network: network,
			iface:   iface,
		},
		c:        c,
		lk:       &sync.Mutex{},
		messages: messages,
		msgChan:  make(chan struct{}, 1),
	}

	go func(p *PacketConn) {
		var msg *dns.Message
		var source net.Addr
		var err error

		for err == nil {
			msg, source, err = p.readFrom()

			p.lk.Lock()
			// XXX ignore malformed message, although there should be a way for the server
			//     to answer with FormError if it wants
			if err != nil && msg == nil {
				p.err = err // connection error
			} else if err == nil {
				p.messages.insertTail(&message{msg: msg, source: source})
			}
			p.lk.Unlock()

			// block sending to this channel for the following reasons:
			// - need a guarantee we can safely read from channel to poll for changed state
			// - back pressure if we are not keeping up with incoming messages
			p.msgChan <- struct{}{}
		}

		close(p.msgChan)
	}(p)

	return p
}

// NewStreamConn creates a stream oriented connection from a net.Conn
func NewStreamConn(c net.Conn, network, iface string) *StreamConn {
	s := &StreamConn{
		conn: &conn{
			network: network,
			iface:   iface,
		},
		c: c,
	}

	return s
}

func (s *StreamConn) String() string {
	return s.c.LocalAddr().String()
}

// NewConnection creates a new Conn instance with a net.Conn or net.PacketConn
func NewConn(conn net.Conn, network, iface string) Conn {
	if p, ok := conn.(net.PacketConn); ok {
		return NewPacketConn(p, network, iface)
	} else {
		return NewStreamConn(conn, network, iface)
	}
}

func (p *PacketConn) String() string {
	return p.c.LocalAddr().String()
}

// Interface returns the interface name given
func (c *conn) Interface() string {
	return c.iface
}

// Network returns the network this connection was created with
func (c *conn) Network() string {
	return c.network
}

// WriteTo sends a *dns.Message. If the message could not fit but could stil be validly sent with reduced extra records,
// Write returns nil but will update msg with what it actually sent.
// msgSize is the maximum message size to fit the message.
func (p *PacketConn) WriteTo(msg *dns.Message, addr net.Addr, msgSize int) error {
	var msgBuf []byte

	if msgSize < MinMessageSize || msgSize > MaxMessageSize {
		panic("rediculous msgSize")
	}

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

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
			msg.TC = true
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
		_, err = p.c.WriteTo(msgBuf, addr)
	} else {
		c, ok := p.c.(net.Conn)
		if !ok {
			return ErrNotConn
		}
		_, err = c.Write(msgBuf)
	}

	return err
}

// addr must be nil. msgSize should be MaxMessageSize
func (s *StreamConn) WriteTo(msg *dns.Message, addr net.Addr, msgSize int) error {
	var msgBuf []byte

	if msgSize < MinMessageSize || msgSize > MaxMessageSize {
		panic("rediculous msgSize")
	}

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	msgBuf = buffer[2 : 2+msgSize]

	if !msg.QR && msg.ID == 0 {
		msg.ID = uint16(atomic.AddUint32(&s.conn.xid, 1))
	}

	writer := dns.NewWireCodec(msgBuf)
	err := writer.Encode(msg)
	if err != nil {
		return err
	}

	msgBuf = msgBuf[:writer.Offset()]
	s.c.SetWriteDeadline(time.Now().Add(5 * time.Minute))
	binary.BigEndian.PutUint16(buffer, uint16(len(msgBuf)))
	msgBuf = buffer[0 : writer.Offset()+2]
	_, err = s.c.Write(msgBuf)

	return err
}

// ReadFromIf receives a *dns.Message, returning the message and, if unconnected, the source address.
// match should be quick. The connection is locked during its call.
func (p *PacketConn) ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, net.Addr, error) {
	var err error

	p.lk.Lock()
	for err == nil {
		err = p.err

		// first check unclaimed baggage
		for m := p.messages.next; m != p.messages; m = m.next {
			if match(m.msg) {
				m.remove()
				p.lk.Unlock()

				return m.msg, m.source, nil
			}
		}

		// wait for new message or error
		for p.messages.empty() && err == nil {
			p.lk.Unlock()

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-p.msgChan:
			}

			p.lk.Lock()
			err = p.err
		}
	}
	p.lk.Unlock()

	return nil, nil, err
}

func (s *StreamConn) ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, net.Addr, error) {
	var msgBuf []byte
	var err error

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	for {
		s.c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		if _, err = io.ReadFull(s.c, buffer[:2]); err != nil {
			return nil, nil, err
		}
		length := int(binary.BigEndian.Uint16(buffer))
		if length > len(buffer) {
			// we create buffers of a size which fit 16 bit lengths..
			panic("short buffer put back in pool?")
		}
		msgBuf = buffer[:length]
		if _, err = io.ReadFull(s.c, msgBuf); err != nil {
			return nil, nil, err
		}

		reader := dns.NewWireCodec(msgBuf)
		msg := &dns.Message{}
		err = reader.Decode(msg)

		if err != nil || match == nil || match(msg) {
			return msg, nil, err
		}
	}
}

func (p *PacketConn) readFrom() (*dns.Message, net.Addr, error) {
	var msgBuf []byte
	var from net.Addr
	var err error

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	var r int
	r, from, err = p.c.ReadFrom(buffer)
	if err != nil {
		return nil, nil, err
	}
	msgBuf = buffer[:r]

	reader := dns.NewWireCodec(msgBuf)
	msg := &dns.Message{}
	err = reader.Decode(msg)
	return msg, from, err
}

// Close closes the underlying conn
func (p *PacketConn) Close() error {
	err := p.c.Close()
	for _ = range p.msgChan {
		// bleed it out until closed
		// (allows producer to proceed and ultimately close channel, also releasing blocked readers)
	}
	return err
}

func (s *StreamConn) Close() error {
	return s.c.Close()
}
