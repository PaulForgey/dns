package test

import (
	"net"
	"sync"
	"time"

	"tessier-ashpool.net/dns/dnsconn"
)

// the Conn type implements the net.Conn interface for in-memory unit testing of network components
type Conn struct {
	*conn
}

// the Listener type implements the net.Listener interface for in-memory unit testing of network copnents
type Listener struct {
	*conn
}

// the PacketConn type implements the net.PacketConn interface for in-memory unit testing of network components
type PacketConn struct {
	*conn
	group string
}

// the Addr type implements the net.Addr interface and is used as addresses with Conn
type Addr struct {
	Name  string
	Group bool   // true if this is a group name
	Net   string // "testpacket" or "test"
}

func (a *Addr) String() string  { return a.Name }
func (a *Addr) Network() string { return a.Net }

var (
	endpointLock sync.RWMutex
	endpoints    = make(map[Addr]*conn)
	groups       = make(map[string][]*conn)
)

type state int

const (
	normal state = iota
	closed
	listen
	connecting
)

type conn struct {
	sync.Mutex
	waiters []chan struct{}
	input   *queue
	closed  chan struct{}
	state   state
	peer    *conn
	addr    *Addr
}

type queue struct {
	payload    []byte
	from       *conn
	next, prev *queue
}

// ResolveAddr creates a Addr
func ResolveAddr(network, name string) (*Addr, error) {
	switch network {
	case "test", "testpacket":
	default:
		return nil, dnsconn.ErrInvalidAddr
	}

	return &Addr{Name: name, Net: network}, nil
}

// Dial establishes a connection to an endpoint created with Listen
func Dial(lname, rname string) (*Conn, error) {
	endpointLock.RLock()
	rconn, ok := endpoints[Addr{Name: rname, Net: "test"}]
	endpointLock.RUnlock()

	if !ok {
		return nil, dnsconn.ErrNoAddr
	}

	rconn.Lock()
	if rconn.state != listen || (rconn.addr != nil && rconn.addr.Net != "test") {
		rconn.Unlock()
		return nil, dnsconn.ErrInvalidState
	}
	rconn.Unlock()

	conn := &Conn{
		conn: newConn(connecting, nil, &Addr{Name: lname, Net: "test"}),
	}

	err := rconn.writeFrom(nil, conn.conn)
	if err != nil {
		return nil, err
	}

	conn.Lock()
	err = conn.waitQueue_locked()
	if err == nil {
		_, conn.peer, err = conn.input.readFrom(nil)
		if conn.state == connecting {
			conn.state = normal
		}
	}
	conn.Unlock()

	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// Listen creates a Conn listener
func Listen(lname string) (*Listener, error) {
	laddr := &Addr{Name: lname, Net: "test"}
	l := &Listener{
		conn: newConn(listen, nil, laddr),
	}

	endpointLock.Lock()
	defer endpointLock.Unlock()

	if _, ok := endpoints[*laddr]; ok {
		return nil, dnsconn.ErrAddrInUse
	}
	endpoints[*laddr] = l.conn

	return l, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	return l.Accept()
}

func (l *Listener) AcceptConn() (*Conn, error) {
	l.Lock()
	defer l.Unlock()

	if err := l.waitQueue_locked(); err != nil {
		return nil, err
	}

	_, peer, err := l.input.readFrom(nil)
	if err != nil {
		return nil, err
	}

	a := &Conn{
		conn: newConn(normal, peer, l.conn.addr),
	}

	peer.writeFrom(nil, a.conn)

	return a, nil
}

func (l *Listener) Addr() net.Addr {
	return l.LocalAddr()
}

// NewConn creates a pair of connected Conns.
// The endpoint names can be anything and are not globally visible
func NewConn(lname, rname string) (*Conn, *Conn) {
	laddr := &Addr{Name: lname, Net: "test"}
	raddr := &Addr{Name: rname, Net: "test"}
	l := &Conn{
		conn: newConn(normal, nil, laddr),
	}
	r := &Conn{
		conn: newConn(normal, nil, raddr),
	}
	l.conn.peer = r.conn
	r.conn.peer = l.conn

	return l, r
}

// ListPacketConn creates a packet based listener
func ListenPacketConn(lname string) (*PacketConn, error) {
	laddr := &Addr{Name: lname, Net: "testpacket"}
	p := &PacketConn{
		conn: newConn(normal, nil, laddr),
	}

	endpointLock.Lock()
	defer endpointLock.Unlock()
	if _, ok := endpoints[*laddr]; ok {
		return nil, dnsconn.ErrAddrInUse
	}
	endpoints[*laddr] = p.conn
	return p, nil
}

// DialPacketConn creates a PacketConn "connected" to another
func DialPacketConn(lname, rname string) (*PacketConn, error) {
	laddr := &Addr{Name: lname, Net: "testpacket"}
	raddr := &Addr{Name: rname, Net: "testpacket"}

	endpointLock.Lock()
	defer endpointLock.Unlock()

	p := &PacketConn{
		conn: newConn(normal, nil, laddr),
	}
	_, ok := endpoints[*laddr]
	if ok {
		return nil, dnsconn.ErrAddrInUse
	}
	p.conn.peer, ok = endpoints[*raddr]
	if !ok {
		return nil, dnsconn.ErrNoAddr
	}
	endpoints[*laddr] = p.conn

	return p, nil
}

func newConn(state state, peer *conn, addr *Addr) *conn {
	return &conn{
		input:  newQueue(),
		closed: make(chan struct{}),
		state:  state,
		peer:   peer,
		addr:   addr,
	}
}

func newQueue() *queue {
	q := &queue{}
	q.next, q.prev = q, q
	return q
}

// all queue access functions assume a lock is held

func (q *queue) popHead() *queue {
	if q.next == q {
		return nil
	}
	e := q.next
	e.prev.next, e.next.prev = e.next, e.prev

	return e
}

func (q *queue) head() *queue {
	if q.next == q {
		return nil
	}
	return q.next
}

func (q *queue) pushTail(e *queue) {
	e.prev, e.next = q.prev, q
	e.prev.next, e.next.prev = e, e
}

func (q *queue) readFrom(p []byte) (int, *conn, error) {
	e := q.popHead()
	if e == nil {
		return 0, nil, nil
	}
	n := copy(p, e.payload)

	return n, e.from, nil
}

func (q *queue) read(p []byte) (int, error) {
	n := 0
	for {
		e := q.head()
		if e == nil {
			break
		}
		r := copy(p, e.payload)
		e.payload = e.payload[r:]
		p = p[r:]
		n += r
		if len(e.payload) > 0 {
			break
		}
		e = q.popHead()
	}
	return n, nil
}

func (q *queue) writeFrom(p []byte, from *conn) {
	e := &queue{}
	e.payload = make([]byte, len(p))
	copy(e.payload, p)
	e.from = from
	q.pushTail(e)
}

func (c *conn) Close() error {
	c.Lock()
	defer c.Unlock()

	if c.state == closed {
		return dnsconn.ErrClosed
	}

	if c.addr != nil && c.addr.Net == "testpacket" || (c.addr.Net == "test" && c.state == listen) {
		endpointLock.Lock()
		delete(endpoints, *c.addr)
		endpointLock.Unlock()
	}

	c.state = closed
	close(c.closed)

	return nil
}

func (c *conn) writeFrom(b []byte, from *conn) error {
	c.Lock()
	defer c.Unlock()

	if c.state == closed {
		return dnsconn.ErrClosed
	}

	c.input.writeFrom(b, from)
	for _, ch := range c.waiters {
		close(ch)
	}
	c.waiters = c.waiters[:0]
	return nil
}

func (c *conn) waitQueue_locked() error {
	var pclosed <-chan struct{}

	if c.peer != nil {
		pclosed = c.peer.closed
	}

	for c.input.head() == nil {
		if c.state == closed {
			return dnsconn.ErrClosed
		}
		ch := make(chan struct{})
		c.waiters = append(c.waiters, ch)
		c.Unlock()

		select {
		case <-c.closed:
			c.Lock()
			return dnsconn.ErrClosed
		case <-pclosed:
			c.Lock()
			return dnsconn.ErrClosed
		case <-ch:
		}

		c.Lock()
	}
	return nil
}

func (c *conn) Read(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()

	err := c.waitQueue_locked()
	if err != nil {
		return 0, err
	}
	return c.input.read(b)
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.Lock()
	defer c.Unlock()

	err := c.waitQueue_locked()
	if err != nil {
		return 0, nil, err
	}
	n, from, err := c.input.readFrom(b)
	var addr *Addr
	if from != nil {
		addr = from.addr
	}
	return n, addr, err
}

func (c *Conn) Write(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()

	if c.peer == nil {
		return 0, dnsconn.ErrNotConn
	}
	err := c.peer.writeFrom(b, nil)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *PacketConn) Write(b []byte) (int, error) {
	c.Lock()
	peer := c.peer
	conn := c.conn
	c.Unlock()

	if peer == nil {
		return 0, dnsconn.ErrNotConn
	}

	err := peer.writeFrom(b, conn)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *PacketConn) WriteTo(b []byte, to net.Addr) (int, error) {
	name, ok := to.(*Addr)
	if !ok || name == nil || name.Net != "testpacket" {
		return 0, dnsconn.ErrInvalidAddr
	}

	c.Lock()

	peer := c.peer
	conn := c.conn

	c.Unlock()

	if peer != nil {
		return 0, dnsconn.ErrIsConn
	}

	endpointLock.RLock()
	peer, ok = endpoints[*name]
	endpointLock.RUnlock()

	if !ok {
		return 0, dnsconn.ErrNoAddr
	}

	err := peer.writeFrom(b, conn)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *conn) LocalAddr() net.Addr {
	return c.addr
}

func (c *conn) RemoteAddr() net.Addr {
	c.Lock()
	defer c.Unlock()

	if c.peer != nil {
		return c.peer.addr
	}

	return nil
}

// XXX TODO
func (c *conn) SetDeadline(t time.Time) error {
	return nil
}

// XXX TODO
func (c *conn) SetReadDeadline(t time.Time) error {
	return nil
}

// XXX TODO
func (c *conn) SetWriteDeadline(t time.Time) error {
	return nil
}
