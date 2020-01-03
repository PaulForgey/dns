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
)

var ErrNoRecords = errors.New("no matching records") // returned only by specialized Lookup methods
var ErrLameDelegation = errors.New("lame delegation")
var ErrNoRecursion = errors.New("recursion denied")

const qtimeout = 5 * time.Second

type Resolver struct {
	lk       *sync.Mutex
	conn     *dnsconn.Connection
	zone     *Zone
	answer   chan struct{}
	servers  []net.Addr
	rd       bool
	ra       bool
	hostType dns.RRType
	debug    dns.Codec
}

func (r *Resolver) init(conn *dnsconn.Connection, zone *Zone, network string) {
	r.lk = &sync.Mutex{}
	r.zone = zone
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
// If zone is nil (not recommended), the resolver will not have a cache. A resolver client should at least have an empty
// root zone to cache results in.
func NewResolverClient(zone *Zone, network string, host string, servers []net.Addr) (*Resolver, error) {
	var conn net.Conn
	var err error

	if network == "" {
		network = "udp"
	}
	if host != "" {
		if conn, err = net.Dial(network, host); err != nil {
			return nil, err
		}
	} else {
		if conn, err = net.ListenUDP(network, nil); err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, err
	}

	r := &Resolver{}
	r.init(dnsconn.NewConnection(conn, network), zone, network)
	r.rd = true
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
func NewResolver(zone *Zone, conn *dnsconn.Connection, ra bool) *Resolver {
	r := &Resolver{}
	r.init(conn, zone, conn.Network)
	r.ra = ra
	return r
}

// Close closes the underlying connection
func (r *Resolver) Close() error {
	return r.conn.Close()
}

// Debug attaches a codec to queries and responses
func (r *Resolver) Debug(c dns.Codec) {
	r.debug = c
}

func (r *Resolver) ask(dest net.Addr, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (uint16, error) {
	id := r.conn.NewMessageID()
	msg := &dns.Message{
		ID:     id,
		Opcode: dns.StandardQuery,
		RD:     r.rd,
		Questions: []*dns.Question{
			&dns.Question{
				QName:  name,
				QType:  rrtype,
				QClass: rrclass,
			},
		},
		EDNS: &dns.Record{
			RecordHeader: dns.RecordHeader{
				MaxMessageSize: dnsconn.UDPMessageSize,
				Version:        0,
			},
			RecordData: &dns.EDNSRecord{},
		},
	}

	err := r.conn.WriteTo(msg, dest, dnsconn.MinMessageSize)
	return id, err
}

func (r *Resolver) waitAnswer(ctx context.Context, id uint16, zone *Zone) (*dns.Message, error) {
	var msg *dns.Message
	var err error

	readCtx, cancel := context.WithTimeout(ctx, qtimeout)
	msg, _, err = r.conn.ReadFromIf(readCtx, func(m *dns.Message) bool {
		return m.QR && m.ID == id
	})
	cancel()

	if msg != nil {
		if zone != nil && msg.RCode == dns.NoError {
			zone.Enter(msg.Answers)
			zone.Enter(msg.Authority)
			zone.Enter(msg.Additional)
		}

		if r.debug != nil {
			r.debug.Encode(msg)
		}
	}

	return msg, err
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
	var servers []net.Addr
	r.lk.Lock()
	if len(r.servers) > 1 {
		// round robin servers if we have several
		top := r.servers[0]
		copy(r.servers, r.servers[1:])
		r.servers[len(r.servers)-1] = top
	}
	servers = r.servers
	r.lk.Unlock()
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
	if r.zone != nil && name.HasSuffix(r.zone.Name) {
		if !r.ra && r.zone.Hint {
			err = ErrNoRecursion
			return
		}
		a, ns, err = r.zone.Lookup(key, name, rrtype, rrclass)
		if len(a) > 0 || len(servers) == 0 || !r.ra {
			// cached answer, cache only, or delegation with recursion not allowed
			return
		}
	}

	// if servers is empty, we did a cache only query
	var msg *dns.Message
	for _, dest := range servers {
		var id uint16
		id, err = r.ask(dest, name, rrtype, rrclass)
		if err != nil {
			continue
		}
		// An error at this point will be a transport error.
		// Any server error is in the successfully received message.
		msg, err = r.waitAnswer(ctx, id, r.zone)

		// see if we are being coerced into a TCP query
		if err == nil && len(msg.Answers) == 0 && len(msg.Authority) == 0 && msg.TC {
			if udpaddr, ok := dest.(*net.UDPAddr); ok {
				var tcp *Resolver
				tcp, err = NewResolverClient(r.zone, "tcp", udpaddr.String(), nil)
				tcp.Debug(r.debug)
				if err != nil {
					return
				}
				a, ns, ar, aa, err = tcp.Query(ctx, key, name, rrtype, rrclass)
				tcp.Close()

				return
			}
		}
		// use first successful server transaction
		if err == nil {
			break
		}
	}
	if err != nil {
		// none of the servers succeeded
		return
	}
	if msg != nil {
		if msg.RCode == dns.NoError {
			// successful answer from server
			a, ns, ar, aa = msg.Answers, msg.Authority, msg.Additional, msg.AA
		} else {
			// now propegate the server response as error
			err = msg.RCode
		}
	} // else obviously cache only

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

	a, err := r.Resolve(ctx, key, name, r.hostType, rrclass)
	if err != nil {
		return nil, err
	}
	for _, r := range a {
		if ip, ok := r.RecordData.(dns.IPRecordType); ok {
			results = append(results, ip)
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
	var records []*dns.Record
	var types []dns.RRType

	if r.hostType == dns.AnyType {
		types = []dns.RRType{dns.AType, dns.AAAAType}
	} else {
		types = []dns.RRType{r.hostType}
	}

	for _, t := range types {
		recs, _, _, _, err := r.query(ctx, servers, key, name, t, rrclass)
		if err != nil {
			return nil, err
		}

		records = append(records, recs...)
	}

	for _, r := range records {
		if ip, ok := r.RecordData.(dns.IPRecordType); ok {
			results = append(results, ip)
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

	seen := make(map[string]bool)
	names := []dns.Name{name}

	for len(names) > 0 {
		n := names[0]
		names = names[1:]

		var result []*dns.Record
		if result, err = r.resolve(ctx, key, n, rrtype, rrclass); err != nil {
			continue
		}
		records = append(records, result...)

		// handle CNAMEs, being careful to chase them once.
		// CNAMEs should not point to CNAMEs, but they can.
		// Just return the CNAME records if we are specifically asking for them, of course.
		if rrtype != dns.CNAMEType && len(result) > 0 {
			var cnames []dns.Name

			for _, r := range result {
				seen[r.RecordHeader.Name.Key()] = true // seen in answer
			}

			// do not chase names which:
			// 1) we already chased
			// 2) had their names already provided in this result or a prior one
			for _, r := range result {
				if c, ok := r.RecordData.(*dns.CNAMERecord); ok {
					if !seen[c.Name.Key()] {
						seen[c.Name.Key()] = true // chased
						cnames = append(cnames, c.Name)
					}
				}
			}

			// ideally, cnames should have 0 or 1 entries unless the domain has a bofh
			names = append(names, cnames...)
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

	if r.rd {
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
			if len(ns) == 0 {
				// we have no ns records for suffix, so keep going down until we do
				for len(suffix) > 0 {
					suffix = suffix.Suffix()
					a, ns, _, _, err = r.query(ctx, nsaddrs, key, suffix, dns.NSType, rrclass)
					if err != nil {
						return nil, err
					}
					if len(a) > 0 || len(ns) > 0 {
						// either an answer happend or we have delgation
						break
					}
				}
			}
			// at this point, we have the list of ns records for suffix

			var authority []dns.NSRecordType
			var aname dns.Name

			for _, record := range append(a, ns...) {
				if auth, ok := record.RecordData.(dns.NSRecordType); ok {
					if len(aname) == 0 {
						aname = record.RecordHeader.Name
					} else if !aname.Equal(record.RecordHeader.Name) {
						return nil, fmt.Errorf(
							"%w: authority section contains %v != %v",
							ErrLameDelegation,
							record.RecordHeader.Name,
							aname,
						)
					}
					authority = append(authority, auth)
				}
			}

			if len(authority) == 0 {
				// no delegation
				return nil, dns.NameError
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
			nsaddrs = nil
			a = nil

			var ips []dns.IPRecordType
			var err error

			// look up the server to ask next iteration
			for _, auth := range authority {
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
				break
			}
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, dns.NameError
			}
			for _, ip := range ips {
				nsaddrs = append(nsaddrs, &net.UDPAddr{
					IP:   ip.IP(),
					Port: 53,
				})
			}
		}
	}

	if rrtype == dns.AnyType && len(a) > 0 {
		for _, rr := range a {
			if hinfo, ok := rr.RecordData.(*dns.HINFORecord); ok && hinfo.CPU == "RFC8482" {
				a, err = r.resolve(ctx, key, name, dns.AType, rrclass)
				if err != nil {
					return nil, err
				}
				// do not ask for the others if CNAME'd
				cname := false
				for _, ar := range a {
					_, cname = ar.RecordData.(*dns.CNAMERecord)
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
