package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/nsdb"
)

var ErrLameDelegation = errors.New("lame delegation")
var ErrNoRecursion = errors.New("recursion denied")

const MaxCNAME = 20 // maximum length of CNAME chain to follow

var debugLk sync.Mutex

type ConnectionError struct {
	err error
}

func (e ConnectionError) Error() string {
	return e.err.Error()
}

func (e ConnectionError) Unwrap() error {
	return e.err
}

const qtimeout = 5 * time.Second

type Resolver struct {
	lk        *sync.Mutex
	conn      dnsconn.Conn
	auth      Authority
	answer    chan struct{}
	servers   []net.Addr
	recursive bool
	rd        bool
	ra        bool
	hostType  dns.RRType
	debug     dns.Codec
}

func (r *Resolver) init(conn dnsconn.Conn, auth Authority, network string) {
	r.lk = &sync.Mutex{}
	r.auth = auth
	r.conn = conn

	// which type of address records to ask for when resolving hosts
	switch network {
	case "udp4", "tcp4", "ip4":
		r.hostType = dns.AType
	default:
		r.hostType = dns.AnyType
	}
}

// NewResolverClient creates a resolver for specific servers intended for external recrusive resolvers or tcp queries.
// If the host parameter is not empty, the resolver will connect to the server as per net.Dial(network, host).
// Otherwise, a UDP connetion is created using the specified network, and servers contains a list of possible servers to query.
// servers is usually nil if host is specified as it would make no sense to send a message on a connected conn to a destination.
// If auth is nil (not recommended), the resolver will not have a cache. A resolver client should at least have an empty
// root zone to cache results in.
// if rd is false, the client will ask questions without the RD flag. This flag is normally set.
func NewResolverClient(auth Authority, network string, host string, servers []net.Addr, rd bool) (*Resolver, error) {
	var conn dnsconn.Conn
	var err error

	if network == "" {
		network = "udp"
	}
	if host != "" {
		c, err := net.Dial(network, host)
		if err != nil {
			return nil, ConnectionError{err}
		}
		conn = dnsconn.NewStreamConn(c, network, "") // even for packet based to save demux overhead
	} else {
		c, err := net.ListenPacket(network, "")
		if err != nil {
			return nil, ConnectionError{err}
		}
		conn = dnsconn.NewPacketConn(c, network, "")
	}
	if err != nil {
		return nil, err
	}

	r := &Resolver{}
	r.init(conn, auth, network)
	r.rd = rd
	r.recursive = false
	r.ra = true
	if host != "" && len(servers) == 0 {
		r.servers = []net.Addr{nil} // hack to indicate connected conn as we send to the nil address
	} else {
		r.servers = servers
	}

	return r, nil
}

// NewResolver a recursive/authoritative resolver.
// If ra is false, recusion is disabled and only authoritative records will be returned
func NewResolver(auth Authority, conn dnsconn.Conn, ra bool) *Resolver {
	r := &Resolver{}
	r.init(conn, auth, conn.Network())
	r.recursive = true
	r.ra = ra
	return r
}

// Conn returns the underlying connection
func (r *Resolver) Conn() dnsconn.Conn {
	return r.conn
}

// Close closes the underlying connection
func (r *Resolver) Close() error {
	return r.conn.Close()
}

// Debug attaches a codec to queries and responses
func (r *Resolver) Debug(c dns.Codec) {
	r.debug = c
}

// Transact sends and receives a DNS query to dest, filling in msg.EDNS as necessary
func (r *Resolver) Transact(ctx context.Context, dest net.Addr, msg *dns.Message) (*dns.Message, error) {
	if dest == nil {
		servers := r.rotate()
		if len(servers) > 0 {
			dest = servers[0]
		}
	}
	outSize := dnsconn.MinMessageSize
	if r.conn.VC() {
		outSize = dnsconn.MaxMessageSize
	} else {
		if msg.EDNS == nil {
			msg.EDNS = dns.NewEDNS(uint16(dnsconn.UDPMessageSize), 0, 0, 0)
		}
	}
	if err := r.conn.WriteTo(msg, dest, outSize); err != nil {
		return nil, err
	}
	return r.Receive(ctx, msg.ID)
}

// Receive returns the next answer of a given message ID (used only with tcp zone transfer)
func (r *Resolver) Receive(ctx context.Context, id uint16) (*dns.Message, error) {
	msg, _, err := r.conn.ReadFromIf(ctx, func(m *dns.Message) bool {
		return m.QR && m.ID == id
	})
	if r.debug != nil {
		debugLk.Lock()
		defer debugLk.Unlock()
	}
	if msg != nil {
		if r.debug != nil {
			r.debug.Encode(msg)
		}
		if msg.RCode != dns.NoError {
			err = msg.RCode
		}
	} else if r.debug != nil && err != nil {
		r.debug.Debug(err.Error())
	}
	return msg, err
}

// Ask sends a StandardQuery to dest, caching any results
func (r *Resolver) Ask(
	ctx context.Context,
	zone ZoneAuthority,
	dest net.Addr,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (*dns.Message, error) {
	msg := &dns.Message{
		Opcode: dns.StandardQuery,
		RD:     r.rd,
		Questions: []dns.Question{
			dns.NewDNSQuestion(name, rrtype, rrclass),
		},
	}

	readCtx, cancel := context.WithTimeout(ctx, qtimeout)
	msg, err := r.Transact(readCtx, dest, msg)
	cancel()

	if msg != nil && zone != nil {
		if msg.RCode == dns.NXDomain {
			now := time.Now()
			zone.Enter(now, "", msg.Authority)
			for _, r := range msg.Authority {
				if r.Type() == dns.SOAType {
					if soa, _ := r.D.(*dns.SOARecord); soa != nil {
						zone.NEnter(now.Add(soa.Minimum), name)
						break
					}
				}
			}
		} else if msg.RCode == dns.NoError {
			now := time.Now()
			// Enter will sort the records
			zone.Enter(now, "", dns.Copy(msg.Answers))
			zone.Enter(now, "", dns.Copy(msg.Authority))
			zone.Enter(now, "", dns.Copy(msg.Additional))
		}
	}

	return msg, err
}

func (r *Resolver) rotate() []net.Addr {
	var servers []net.Addr
	r.lk.Lock()
	if len(r.servers) > 1 {
		// round robin servers if we have several
		servers = make([]net.Addr, len(r.servers))
		copy(servers, r.servers[1:])
		servers[len(servers)-1] = r.servers[0]
		// swap in a copy to avoid moving the list in place while others use it
		r.servers = servers
	} else {
		servers = r.servers
	}
	r.lk.Unlock()
	return servers
}

// Query sends a query returning the answer, authority, and additional sections or an error.
// The appropriate zone is consulted first, which means the cache is also consulted.
// If the resolver is using a udp network and the answer from the server is truncated with an empty answer section, the
// query will be retried using tcp.
// If the resolver has a list of client addresses, this list will be rotated, and multiple servers will be queried if there
// is an error.
func (r *Resolver) Query(
	ctx context.Context,
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (a []*dns.Record, ns []*dns.Record, ar []*dns.Record, aa bool, err error) {
	servers := r.rotate()
	return r.query(ctx, servers, key, name, rrtype, rrclass)
}

func (r *Resolver) query(
	ctx context.Context,
	servers []net.Addr,
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (a []*dns.Record, ns []*dns.Record, ar []*dns.Record, aa bool, err error) {

	// always go for the cache or our own authority first
	var zone ZoneAuthority

	if r.auth != nil {
		zone = r.auth.Find(name)
	}

	if zone != nil && name.HasSuffix(zone.Name()) {
		if !r.ra && zone.Hint() {
			err = ErrNoRecursion
			return
		}
		a, ns, err = zone.Lookup(key, name, rrtype, rrclass)
		if errors.Is(err, nsdb.ErrNegativeAnswer) {
			aa = true
			return
		}
		if len(a) > 0 || len(servers) == 0 || !r.ra {
			// cached answer, cache only, or delegation with recursion not allowed
			return
		}
	}

	// if servers is empty, we did a cache only query
	var msg *dns.Message
	if len(servers) > 0 {
		qctx, cancel := context.WithCancel(ctx)
		defer cancel()
		msgs := make(chan *dns.Message, len(servers))
		errs := make(chan error, len(servers))

		for _, dest := range servers {
			go func(dest net.Addr) {
				msg, err := r.Ask(qctx, zone, dest, name, rrtype, rrclass)
				// see if we are being coerced into a TCP query
				if err == nil && len(msg.Answers) == 0 && len(msg.Authority) == 0 && msg.TC {
					if udpaddr, ok := dest.(*net.UDPAddr); ok {
						var tcp *Resolver
						tcp, err = NewResolverClient(r.auth, "tcp", udpaddr.String(), nil, r.rd)
						if err == nil {
							msg, err = tcp.Ask(qctx, zone, nil, name, rrtype, rrclass)
							tcp.Close()
						}
					}
				}
				if err == nil {
					cancel()
				}
				msgs <- msg
				errs <- err
			}(dest)
		}

		// first successful answer, failing that, first error
		for _ = range servers {
			msg = <-msgs
			if msg != nil {
				err = nil
				break
			}
		}
		if msg == nil {
			for _ = range servers {
				err = <-errs
				if err != nil {
					break
				}
			}
		}
		cancel()
	}

	if msg != nil {
		// answer from server
		a, ns, ar, aa = msg.Answers, msg.Authority, msg.Additional, msg.AA
		if msg.RCode != dns.NoError {
			err = msg.RCode
		} else {
			err = nil
		}
	}

	return
}

// ResolveIP is a wrapper around Resolve which returns only address records. The address family of the returned records
// are limited to those compatible with the resolver's network.
func (r *Resolver) ResolveIP(
	ctx context.Context,
	key string,
	name dns.Name,
	rrclass dns.RRClass,
) ([]dns.IPRecordType, error) {
	var results []dns.IPRecordType
	var types []dns.RRType

	if r.hostType == dns.AnyType {
		types = []dns.RRType{dns.AType, dns.AAAAType}
	} else {
		types = []dns.RRType{r.hostType}
	}

	for _, t := range types {
		a, err := r.Resolve(ctx, key, name, t, rrclass)
		if err != nil {
			return nil, err
		}
		for _, r := range a {
			if ip, ok := r.D.(dns.IPRecordType); ok {
				results = append(results, ip)
			}
		}
	}

	return results, nil
}

// resolveIP is like ResolveIP except not recursive
func (r *Resolver) resolveIP(
	ctx context.Context,
	servers []net.Addr,
	key string,
	name dns.Name,
	rrclass dns.RRClass,
) ([]dns.IPRecordType, error) {
	var results []dns.IPRecordType
	var types []dns.RRType

	if r.hostType == dns.AnyType {
		types = []dns.RRType{dns.AType, dns.AAAAType}
	} else {
		types = []dns.RRType{r.hostType}
	}

	for _, t := range types {
		a, _, _, _, err := r.query(ctx, servers, key, name, t, rrclass)
		if err != nil {
			return nil, err
		}

		for _, r := range a {
			if ip, ok := r.D.(dns.IPRecordType); ok {
				results = append(results, ip)
			}
		}
	}

	return results, nil
}

// Resolve attempts to completely answer a question, either recursively or against other recursive servers. If a single CNAME
// is returned and the query is not specifically for CNAME records, the record is followed.
func (r *Resolver) Resolve(
	ctx context.Context,
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, error) {
	var records []*dns.Record
	var err error

	for cnames := 0; cnames < MaxCNAME; cnames++ {
		var result []*dns.Record

		result, err = r.resolve(ctx, key, name, rrtype, rrclass)
		if err != nil {
			break
		}

		records = append(records, result...)
		if rrtype == dns.CNAMEType || len(result) == 0 {
			break
		}
		nname := name
		// if there is more than one cname result, it would be because a chain was given to us
		// (or there are actually more than one, but that would be undefined and bogus)
		// so start at the end to help avoid turning this into n*m
		for n := len(result) - 1; n >= 0; n-- {
			cname, _ := result[n].D.(*dns.CNAMERecord)
			if cname == nil {
				break
			}

			found := false
			for _, r := range records {
				if r.Name().Equal(cname.Name) {
					found = true
					break
				}
			}
			if !found {
				nname = cname.Name
				break
			}
		}
		if !nname.Equal(name) {
			name = nname
		} else {
			break
		}
	}

	return records, err
}

func (r *Resolver) resolve(
	ctx context.Context,
	key string,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) ([]*dns.Record, error) {
	var a, ns []*dns.Record
	var err error
	var aa bool

	if !r.recursive {
		// query external recursive server
		a, ns, _, aa, err = r.Query(ctx, key, name, rrtype, rrclass)
		if err != nil {
			return nil, err
		}
	} else {
		// recursive query

		var progress dns.Name  // keep track of delegation progress
		var nsaddrs []net.Addr // current set of name servers this iteration, start with the cache

		for len(a) == 0 {
			a, ns, _, aa, err = r.query(ctx, nsaddrs, key, name, rrtype, rrclass)
			if err != nil {
				return nil, err
			}
			if aa || len(a) > 0 || len(ns) == 0 {
				// done if we have authoritative anything, answers, or no further delegation
				break
			}

			suffix := name // name to query NS record for
			if rrtype == dns.NSType {
				suffix = suffix.Suffix()
			}
			if len(ns) == 0 {
				// we have no ns records for suffix, so keep going down until we do
				for len(suffix) > 0 {
					a, ns, _, _, err = r.query(ctx, nsaddrs, key, suffix, dns.NSType, rrclass)
					if err != nil {
						return nil, err
					}
					if len(a) > 0 || len(ns) > 0 {
						// either an answer happend or we have delgation
						if len(a) == 0 || a[0].Type() != dns.CNAMEType {
							break
						}
					}
					suffix = suffix.Suffix()
				}
			}
			// at this point, we have the list of ns records for suffix

			var authority []dns.NSRecordType
			var aname dns.Name

			for _, record := range append(a, ns...) {
				if auth, ok := record.D.(dns.NSRecordType); ok {
					if len(aname) == 0 {
						aname = record.Name()
					} else if !aname.Equal(record.Name()) {
						return nil, fmt.Errorf(
							"%w: authority section contains %v != %v",
							ErrLameDelegation,
							record.Name(),
							aname,
						)
					}
					authority = append(authority, auth)
				}
			}

			if len(authority) == 0 {
				// no delegation
				return nil, fmt.Errorf("%w: no delegation for %v", dns.NXDomain, name)
			}
			if !suffix.HasSuffix(aname) || !aname.HasSuffix(progress) {
				// got wrong delegation
				return nil, fmt.Errorf(
					"%w: authority section contains %v, looking for %v (last got %v)",
					ErrLameDelegation,
					aname,
					suffix,
					progress,
				)
			}
			if len(progress) > 0 && len(progress) == len(aname) {
				// did not make forward progress
				return nil, fmt.Errorf(
					"%w: delegation was not helpful making progress from %v",
					ErrLameDelegation,
					progress,
				)
			}
			progress = aname
			a = nil

			var ips []dns.IPRecordType

			// look up the server to ask next iteration
			for _, auth := range authority {
				var err error

				if auth.NS().HasSuffix(aname) {
					// avoid an endless cycle if the glue record is missing
					if ips, err = r.resolveIP(ctx, nsaddrs, key, auth.NS(), rrclass); err != nil {
						continue
					}
				} else {
					if ips, err = r.ResolveIP(ctx, key, auth.NS(), rrclass); err != nil {
						continue
					}
				}
				if len(ips) == 0 {
					continue
				}
				break
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("%w: no nameserver ips", dns.NXDomain)
			}

			nsaddrs = make([]net.Addr, len(ips))
			for i, ip := range ips {
				nsaddrs[i] = &net.UDPAddr{
					IP:   ip.IP(),
					Port: 53,
				}
			}
		}
	}

	if rrtype == dns.AnyType && len(a) > 0 {
		for _, rr := range a {
			if hinfo, ok := rr.D.(*dns.HINFORecord); ok && hinfo.CPU == "RFC8482" {
				a, err = r.resolve(ctx, key, name, dns.AType, rrclass)
				if err != nil {
					return nil, err
				}
				// do not ask for the others if CNAME'd
				cname := false
				for _, ar := range a {
					cname = (ar.H.Type() == dns.CNAMEType)
					if cname {
						// ..ffs, could have answered _that_ instead in the first place.
						// see section 4.2 of RFC8482
						break
					}
				}
				if !cname {
					aaaarec, err := r.resolve(ctx, key, name, dns.AAAAType, rrclass)
					if err != nil {
						return nil, err
					}
					a = append(a, aaaarec...)
				}
				if !cname {
					mxrec, err := r.resolve(ctx, key, name, dns.MXType, rrclass)
					if err != nil {
						return nil, err
					}
					a = append(a, mxrec...)
				}
				break
			}
		}
	}

	return a, nil
}
