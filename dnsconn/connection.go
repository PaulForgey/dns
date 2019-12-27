package dnsconn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"tessier-ashpool.net/dns"
)

const (
	MaxMessageSize = 65535 // 16 bit size field
	MinMessageSize = 512   // bsd BUFSIZ used in ancient times
)

var ErrClosed = errors.New("closed")

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

// insert n before m
func (m *message) insertTail(n *message) {
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

// The Connection type creates a wrapper around a net.Conn for sending and receiving *dns.Message.
type Connection struct {
	conn     net.Conn
	msgSize  int
	udp      bool
	lk       *sync.Mutex
	messages *message
	msgChan  chan struct{}
	xid      uint32
	err      error
}

// NewConnection creates a new Connection instance with a given conn.
// msgSize is the maximum message size to fit an outgoing packet into. Messages are always received in to a buffer
// of the largest possible size.
func NewConnection(conn net.Conn, msgSize int) *Connection {
	if msgSize < MinMessageSize || msgSize > MaxMessageSize {
		panic("rediculous msgSize")
	}
	_, udp := conn.(net.PacketConn)

	// sentinal node
	messages := &message{}
	messages.next = messages
	messages.prev = messages

	c := &Connection{
		conn:     conn,
		msgSize:  msgSize,
		udp:      udp,
		lk:       &sync.Mutex{},
		messages: messages,
		msgChan:  make(chan struct{}, 1),
	}

	go func(c *Connection) {
		var msg *dns.Message
		var source net.Addr
		var err error

		for err == nil {
			msg, source, err = c.readFrom()

			c.lk.Lock()
			if err != nil {
				c.err = err
			} else {
				c.messages.insertTail(&message{msg: msg, source: source})
			}
			c.lk.Unlock()

			// block sending to this channel for the following reasons:
			// - need a guarantee we can safely read from channel to poll for changed state
			// - back pressure if we are not keeping up with incoming messages
			c.msgChan <- struct{}{}
		}

		close(c.msgChan)
	}(c)

	return c
}

// NewMessageID allocates and returns the next message ID
func (c *Connection) NewMessageID() uint16 {
	return uint16(atomic.AddUint32(&c.xid, 1))
}

// WriteTo sends a *dns.Message. If the message could not fit but could stil be validly sent with reduced extra records,
// Write returns nil but will update msg with what it actually sent.
// Use a nil addr for connected conns.
func (c *Connection) WriteTo(msg *dns.Message, addr net.Addr) error {
	var msgBuf []byte

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	if c.udp {
		msgBuf = buffer[:c.msgSize]
	} else {
		msgBuf = buffer[2 : 2+c.msgSize]
	}

	if !msg.QR && msg.ID == 0 {
		msg.ID = c.NewMessageID()
	}

	writer := dns.NewWireCodec(msgBuf)
	err := writer.Encode(msg)
	var truncated *dns.Truncated
	if errors.As(err, &truncated) {
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
		if err := writer.Encode(msg); err != nil {
			return err
		}
	}

	msgBuf = msgBuf[:writer.Offset()]
	if c.udp {
		if addr != nil {
			_, err = c.conn.(net.PacketConn).WriteTo(msgBuf, addr)
		} else {
			_, err = c.conn.Write(msgBuf)
		}
	} else {
		binary.BigEndian.PutUint16(buffer, uint16(len(msgBuf)))
		msgBuf = buffer[0 : writer.Offset()+2]
		_, err = c.conn.Write(msgBuf)
	}

	return err
}

// ReadFromIf receives a *dns.Message, returning the message and, if unconnected, the source address.
// match should be quick. The connection is locked during its call.
func (c *Connection) ReadFromIf(ctx context.Context, match func(*dns.Message) bool) (*dns.Message, net.Addr, error) {
	var err error

	c.lk.Lock()
	for err == nil {
		err = c.err

		// first check unclaimed baggage
		for m := c.messages.next; m != c.messages; m = m.next {
			if match(m.msg) {
				m.remove()
				c.lk.Unlock()

				return m.msg, m.source, nil
			}
		}

		// wait for new message or error
		for c.messages.empty() && err == nil {
			c.lk.Unlock()

			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-c.msgChan:
			}

			c.lk.Lock()
			err = c.err
		}
	}
	c.lk.Unlock()

	return nil, nil, err
}

func (c *Connection) readFrom() (*dns.Message, net.Addr, error) {
	var msgBuf []byte
	var from net.Addr
	var err error

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	if c.udp {
		var r int
		r, from, err = c.conn.(net.PacketConn).ReadFrom(buffer)
		if err != nil {
			return nil, nil, err
		}
		msgBuf = buffer[:r]
	} else {
		if _, err = io.ReadFull(c.conn, buffer[:2]); err != nil {
			return nil, nil, err
		}
		length := int(binary.BigEndian.Uint16(buffer))
		if length > len(buffer) {
			// we create buffers of a size which fit 16 bit lengths..
			panic("short buffer put back in pool?")
		}
		msgBuf = buffer[:length]
		if _, err = io.ReadFull(c.conn, msgBuf); err != nil {
			return nil, nil, err
		}
	}

	reader := dns.NewWireCodec(msgBuf)
	msg := &dns.Message{}
	err = reader.Decode(msg)
	return msg, from, err
}

// Close closes the underlying conn
func (c *Connection) Close() error {
	err := c.conn.Close()
	for _ = range c.msgChan {
		// bleed it out until closed
		// (allows producer to proceed and ultimately close channel, also releasing blocked readers)
	}
	return err
}
