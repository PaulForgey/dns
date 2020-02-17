package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

type ZoneType string

const (
	PrimaryType   ZoneType = "primary"
	SecondaryType ZoneType = "secondary"
	HintType      ZoneType = "hint"
	CacheType     ZoneType = "cache" // same as "hint" but with built-in root
)

var logStderr bool
var confFile string
var cache = ns.NewCacheZone(resolver.NewRootZone())
var logger *log.Logger
var res *resolver.Resolver

type Zone struct {
	Type             ZoneType
	DbFile           string            `json:",omitempty"`
	InterfaceDbFiles map[string]string `json:",omitempty"` // primary: interface specific records
	Primary          string            `json:",omitempty"` // secondary: primary server to transfer from
	Incremental      bool              `json:",omitempty"` // secondary: use IXFR
	Class            dns.RRClass       `json:",omitempty"` // secondary: zone class (has invalid zero value, defaults to ANY)
	AllowQuery       []string
	AllowTransfer    []string
	AllowUpdate      []string
	AllowNotify      []string

	conf   *Conf
	zone   *ns.Zone
	cancel context.CancelFunc
	ctx    context.Context
	wg     sync.WaitGroup
}

type REST struct {
	Addr        string // if empty, listens globally on port 80. Probably not what you want
	AllowGET    []string
	AllowPUT    []string
	AllowDELETE []string
	AllowPOST   []string
	AllowPATCH  []string
	// XXX TLS
}

type Listener struct {
	Network       string // network name, e.g. tcp, udp4
	Address       string // network address, e.g. 127.0.0.1:53
	InterfaceName string // optional interface name for interface specific records (does not have to match actual interface)
	VC            bool   // network is not packet based, that is, it needs to Accept() connections
}

// all conditions must match in an element, any element must match in a list.
// an ACE matches if any of the specified conditions match, or if no conditions are specified.
// that is, an empty ACE means to match all
type CIDR struct {
	net.IPNet
}

// XXX need user authentication options for REST, and once we have DNSSEC (sigh), keys
type ACE struct {
	InterfaceName string `json:",omitempty"` // interface name
	CIDR          *CIDR  `json:",omitempty"` // CIDR mask, if applicable
	Resource      string `json:",omitempty"` // URL path, if applicable
}

// An empty ACL means to deny.
// To deny all, specify an empty ACL. To allow all, specify an ACL with a single empty ACE.
type ACL []ACE

type Conf struct {
	sync.RWMutex

	ACLs              map[string]ACL   // ACLs by name
	Zones             map[string]*Zone // unicast zones
	MDNSZones         map[string]*Zone // mDNS zones
	Resolver          *Listener        `json:",omitempty"` // outgoing queries. Must be udp/udp4/udp6
	REST              *REST            `json:",omitempty"` // REST server; omit or set to null to disable
	Listeners         []Listener       `json:",omitmepty"` // additional or specific listeners
	AutoListeners     bool             // true to automatically discover all interfaces to listen on
	MDNSListeners     []Listener       `json:",omitempty"` // additional or specific mDNS listeners
	AutoMDNSListeners bool             // true to automatically discover all interfaces for mDNS
	MDNSResolver      *Listener        `json:",omitempty"` // IPC listener for mDNS
	AnnounceHost      bool             // true to automatically mDNS advertise A and AAAA records for this host
	AllowRecursion    []string         `json:",omitempty"` // ACLs for recursion

	// XXX global server ACL
}

func (c *CIDR) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if _, ipnet, err := net.ParseCIDR(s); err != nil {
		return err
	} else {
		c.IPNet = *ipnet
	}
	return nil
}

func (c CIDR) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.IPNet.String())
}

func (l *Listener) run(ctx context.Context, wg *sync.WaitGroup, conf *Conf, zones *ns.Zones) {
	allowRecursion := conf.Access(&conf.AllowRecursion)
	if l.VC {
		c, err := net.Listen(l.Network, l.Address)
		if err != nil {
			logger.Println(err)
			return
		}

		logger.Printf("%s: listening %s %v", l.InterfaceName, l.Network, l.Address)
		l.serveListener(ctx, wg, c, func(c dnsconn.Conn) {
			s := ns.NewServer(logger, c, zones, res, allowRecursion)
			s.Serve(ctx)
		})
	} else {
		var conn dnsconn.Conn
		if conf.Resolver != nil &&
			netname(conf.Resolver.Network) == netname(l.Network) &&
			conf.Resolver.Address == l.Address {
			conn = res.Conn()
		} else {
			c, err := net.ListenPacket(l.Network, l.Address)
			if err != nil {
				logger.Println(err)
				return
			}
			conn = dnsconn.NewPacketConn(c, l.Network, l.InterfaceName)
			defer conn.Close()
		}

		logger.Printf("%s: listening %s %v", l.InterfaceName, l.Network, l.Address)
		s := ns.NewServer(logger, conn, zones, res, allowRecursion)
		s.Serve(ctx)
	}
}

func (l *Listener) runMDNS(ctx context.Context, wg *sync.WaitGroup, servers []*ns.Server, mzones *ns.Zones) {
	c, err := net.Listen(l.Network, l.Address)
	if err != nil {
		logger.Println(err)
		return
	}

	logger.Printf("running mDNS resolver on %s %v", l.Network, l.Address)
	l.serveListener(ctx, wg, c, func(c dnsconn.Conn) {
		c.(*dnsconn.StreamConn).MDNS()
		r := ns.NewMResolver(logger, c, servers, mzones, ns.AllAccess, ns.AllAccess)
		r.Serve(ctx)
	})
}

func (l *Listener) serveListener(ctx context.Context, wg *sync.WaitGroup, c net.Listener, serve func(c dnsconn.Conn)) {
	lctx, cancel := context.WithCancel(ctx)
	go func() {
		<-lctx.Done()
		c.Close()
	}()
	for {
		a, err := c.Accept()
		if err != nil {
			logger.Println(err)
			cancel()
			break
		} else {
			actx, cancel := context.WithCancel(lctx)
			go func() {
				<-actx.Done()
				a.Close()
			}()
			wg.Add(1)
			go func() {
				conn := dnsconn.NewStreamConn(a, l.Network, l.InterfaceName)
				serve(conn)
				wg.Done()
				cancel()
			}()
		}
	}
}

func (l *Listener) newMDNS(zones *ns.Zones) *ns.Server {
	conn, err := dnsconn.NewMulticast(l.Network, l.Address, l.InterfaceName)
	if err != nil {
		logger.Printf("multicast: %s/%s: %v", l.Network, l.Address, err)
		return nil
	}
	logger.Printf("mDNS listening %s %v", l.Network, l.Address)
	return ns.NewServer(logger, conn, zones, nil, ns.AllAccess)
}

func netname(network string) string {
	if len(network) > 0 {
		l := len(network) - 1
		n := network[l]
		if n == '4' || n == '6' {
			return network[:l]
		}
	}
	return network
}

func namesForHost(host dns.Name, mzones *ns.Zones) (resolver.OwnerNames, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	names := make(resolver.OwnerNames)

	for _, ifi := range ifaces {
		if (ifi.Flags & dnsconn.FlagsMask) != dnsconn.FlagsMDNS {
			continue
		}

		var records []*dns.Record
		addrs, err := ifi.Addrs()
		if err != nil {
			return nil, err
		}

		nsec := &dns.NSECRecord{Next: host}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP
			ip4 := ip.To4()
			if ip4 != nil {
				nsec.Types.Set(dns.AType)
				rev, err := dns.NameWithString(
					fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa",
						ip4[3], ip4[2], ip4[1], ip4[0]))
				if err != nil {
					return nil, err
				}

				arec := &dns.ARecord{}
				copy(arec.Address[:], ip4)

				records = append(records,
					&dns.Record{
						H: dns.NewMDNSHeader(host, dns.AType, dns.INClass, 120*time.Second, true),
						D: arec,
					},
					&dns.Record{
						H: dns.NewMDNSHeader(rev, dns.PTRType, dns.INClass, 120*time.Second, true),
						D: &dns.PTRRecord{host},
					},
				)
			} else {
				nsec.Types.Set(dns.AAAAType)
				rname := &strings.Builder{}
				for i := len(ip) - 1; i >= 0; i-- {
					rname.WriteString(fmt.Sprintf("%x.%x.", ip[i]&0xf, ip[i]>>4))
				}
				rname.WriteString("ip6.arpa")
				rev, err := dns.NameWithString(rname.String())

				if err != nil {
					return nil, err
				}

				aaaarec := &dns.AAAARecord{}
				copy(aaaarec.Address[:], ip)

				records = append(records,
					&dns.Record{
						H: dns.NewMDNSHeader(host, dns.AAAAType, dns.INClass, 120*time.Second, true),
						D: aaaarec,
					},
					&dns.Record{
						H: dns.NewMDNSHeader(rev, dns.PTRType, dns.INClass, 120*time.Second, true),
						D: &dns.PTRRecord{host},
					},
				)
			}
		}

		records = append(records, &dns.Record{
			H: dns.NewMDNSHeader(host, dns.NSECType, dns.INClass, 120*time.Second, true),
			D: nsec,
		})

		err = names.Enter(mzones, ifi.Name, records)
		if err != nil {
			return nil, err
		}
	}
	return names, nil
}

func announceHost(ctx context.Context, wg *sync.WaitGroup, servers []*ns.Server, mzones *ns.Zones) error {
	hostname, err := os.Hostname()
	if err != nil {
		return err
	}
	h := strings.Split(hostname, ".")
	if len(h) == 0 {
		return errors.New("empty hostname")
	}
	hostname = h[0]

	var names resolver.OwnerNames

	try := 0
	for err == nil {
		var host dns.Name
		if try == 0 {
			host, err = dns.NameWithString(hostname + ".local")
		} else {
			host, err = dns.NameWithString(fmt.Sprintf("%s-%d.local", hostname, try))
		}
		if err != nil {
			return err
		}
		try++

		names, err = namesForHost(host, mzones)
		if err != nil {
			return err
		}

		actx, cancel := context.WithCancel(ctx)
		errch := make(chan error, len(servers))

		for _, s := range servers {
			wg.Add(1)
			go func(s *ns.Server) {
				err := s.Announce(actx, names, cancel)
				if err != nil {
					errch <- err
				}
				wg.Done()
			}(s)
		}

		select {
		case <-ctx.Done():
		case err = <-errch:
			if errors.Is(err, context.Canceled) || errors.Is(err, dns.YXDomain) {
				err = nil
			}
		}
		cancel()

		if err == nil {
			err = ctx.Err()
		}
	}

	if names != nil {
		for _, s := range servers {
			s.Unannounce(names)
		}
	}

	return err
}

func main() {
	var err error
	var conf Conf

	flag.BoolVar(&logStderr, "stderr", false, "log using stderr")
	flag.StringVar(&confFile, "conf", "ns.json", "configuration file location")

	flag.Parse()

	if logStderr {
		hostname, err := os.Hostname()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot get hostname: %v\n", err)
			hostname = "ns"
		}
		logger = log.New(os.Stderr, hostname+":", log.LstdFlags)
	} else {
		logger, err = syslog.NewLogger(syslog.LOG_NOTICE|syslog.LOG_DAEMON, log.LstdFlags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to connect to syslog: %v", err)
			os.Exit(1)
		}
	}

	c, err := os.Open(confFile)
	if err != nil {
		logger.Fatalf("unable to open configuration file: %v", err)
	}

	err = json.NewDecoder(c).Decode(&conf)
	c.Close()
	if err != nil {
		logger.Fatalf("unable to parse configuration file %s: %v", confFile, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ctx2, cancel2 := context.WithCancel(ctx) // cancel this one for cleanup

	wg := &sync.WaitGroup{}
	wg2 := &sync.WaitGroup{} // cleanup work ahead of shutdown

	zones := ns.NewZones()
	mzones := ns.NewZones()

	if conf.Resolver != nil {
		c, err := net.ListenPacket(conf.Resolver.Network, conf.Resolver.Address)
		if err != nil {
			logger.Fatalf("unable to create resolver socket: %v", err)
		}
		res = resolver.NewResolver(zones, dnsconn.NewPacketConn(c, conf.Resolver.Network, ""), true)
	}

	// load all data before running
	for name, c := range conf.Zones {
		err := c.create(ctx, &conf, name)
		if err != nil {
			logger.Fatalf("%s: cannot create zone: %v", name, err)
		}
		zones.Insert(c.zone, c.Type != SecondaryType) // secondary offline until loaded
	}
	for name, c := range conf.MDNSZones {
		err := c.create(ctx, &conf, name)
		if err != nil {
			logger.Fatalf("%s: cannot create zone: %v", name, err)
		}
		mzones.Insert(c.zone, true)
	}

	for _, c := range conf.Zones {
		c.run(zones)
	}
	for _, c := range conf.MDNSZones {
		c.run(mzones)
	}

	if conf.REST != nil {
		wg.Add(1)
		go func() {
			s := &RestServer{
				Server: http.Server{
					Addr: conf.REST.Addr,
				},
				Conf:           &conf,
				Zones:          zones,
				ShutdownServer: cancel,
			}
			s.Serve(ctx)
			wg.Done()
		}()
	}

	if conf.AutoListeners {
		conf.Listeners = append(conf.Listeners,
			Listener{
				Network: "udp4",
				Address: ":53",
				VC:      false,
			},
			Listener{
				Network: "udp6",
				Address: ":53",
				VC:      false,
			},
			Listener{
				Network: "tcp4",
				Address: ":53",
				VC:      true,
			},
			Listener{
				Network: "tcp6",
				Address: ":53",
				VC:      true,
			},
		)
	}
	if conf.AutoMDNSListeners {
		conf.MDNSListeners = append(conf.MDNSListeners,
			Listener{
				Network: "udp4",
				Address: ":5353",
			},
			Listener{
				Network: "udp6",
				Address: ":5353",
			},
		)
	}

	for _, l := range conf.Listeners {
		wg.Add(1)
		go func(l Listener) {
			l.run(ctx, wg, &conf, zones)
			wg.Done()
		}(l)
	}

	servers := make([]*ns.Server, 0, len(conf.MDNSListeners))
	for _, l := range conf.MDNSListeners {
		if s := l.newMDNS(mzones); s != nil {
			servers = append(servers, s)
		}
	}

	for _, s := range servers {
		wg.Add(1)
		go func(s *ns.Server) {
			s.ServeMDNS(ctx)
			s.Close()
			wg.Done()
		}(s)
	}

	if conf.MDNSResolver != nil {
		wg2.Add(1)
		go func() {
			conf.MDNSResolver.runMDNS(ctx2, wg, servers, mzones)
			wg2.Done()
		}()
	}

	if conf.AnnounceHost {
		wg2.Add(1)
		go func() {
			err := announceHost(ctx2, wg2, servers, mzones)
			logger.Printf("mDNS host annoucement: %v", err)
			wg2.Done()
		}()
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	select {
	case sig := <-sigc:
		logger.Printf("shutting down on %v", sig)
		cancel2()
		wg2.Wait()
		logger.Printf("cleanup done, shutting down")
		cancel()
	case <-ctx.Done():
		logger.Printf("shutting down by request")
	}

	signal.Stop(sigc)

	if res != nil {
		res.Close()
	}

	for _, c := range conf.Zones {
		c.wait()
	}
	wg.Wait()

	logger.Printf("exiting: %v", ctx.Err())
}
