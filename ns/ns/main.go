package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"

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
	MDNSZones         map[string]*Zone // MDNS zones
	Resolver          string           // udp,udp4,udp6 empty for no recursive resolver
	REST              *REST            `json:",omitmepyt"` // REST server; omit or set to null to disable
	Listeners         []Listener       `json:",omitmepty"` // additional or specific listeners
	AutoListeners     bool             // true to automatically discover all interfaces to listen on
	MDNSListeners     []Listener       `json:",omitempty"` // additional or specific MDNS listeners
	AutoMDNSListeners bool             // true to automatically discover all interfaces for MDNS
	AllowRecursion    []string         `json:",omitempty"` // ACLs for recursion

	// XXX global server ACL
	// XXX mdns zone
}

var logStderr bool
var confFile string
var cache = ns.NewCacheZone(resolver.NewRootZone())
var logger *log.Logger

func (l *Listener) run(ctx context.Context, wg *sync.WaitGroup, conf *Conf, zones *ns.Zones, res *resolver.Resolver) {
	allowRecursion := conf.Access(&conf.AllowRecursion)
	if l.VC {
		c, err := net.Listen(l.Network, l.Address)
		if err != nil {
			logger.Println(err)
			return
		}

		logger.Printf("%s: listening %s %v", l.InterfaceName, l.Network, l.Address)
		closer := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
			case <-closer:
			}
			c.Close()
		}()
		for {
			a, err := c.Accept()
			if err != nil {
				logger.Println(err)
				close(closer)
				break
			} else {
				closer := make(chan struct{})
				go func() {
					select {
					case <-ctx.Done():
					case <-closer:
					}
					a.Close()
				}()
				wg.Add(1)
				go func() {
					conn := dnsconn.NewStreamConn(a, l.Network, l.InterfaceName)
					s := ns.NewServer(logger, conn, zones, res, allowRecursion)
					s.Serve(ctx)
					wg.Done()
					close(closer)
				}()
			}
		}
	} else {
		c, err := net.ListenPacket(l.Network, l.Address)
		if err != nil {
			logger.Println(err)
			return
		}
		logger.Printf("%s: listening %s %v", l.InterfaceName, l.Network, l.Address)
		conn := dnsconn.NewPacketConn(c, l.Network, l.InterfaceName)
		s := ns.NewServer(logger, conn, zones, res, allowRecursion)
		s.Serve(ctx)
		conn.Close()
	}
}

func (l *Listener) runMDNS(ctx context.Context, zones *ns.Zones) {
	ifi, err := net.InterfaceByName(l.InterfaceName)
	if err != nil {
		logger.Printf("%s: %v", l.InterfaceName, err)
		return
	}
	conn, err := dnsconn.NewMulticast(l.Network, l.Address, ifi)
	if err != nil {
		logger.Printf("%s: %v", l.InterfaceName, err)
		return
	}
	s := ns.NewServer(logger, conn, zones, nil, ns.AllAccess)
	s.ServeMDNS(ctx)
	conn.Close()
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
	wg := &sync.WaitGroup{}
	zones := ns.NewZones()
	mzones := ns.NewZones()
	var res *resolver.Resolver

	if conf.Resolver != "" {
		rc, err := net.ListenUDP(conf.Resolver, &net.UDPAddr{})
		if err != nil {
			logger.Fatalf("unable to create resolver socket: %v", err)
		}
		res = resolver.NewResolver(zones, dnsconn.NewConn(rc, conf.Resolver, ""), true)
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
		c.run(zones, res)
	}
	for _, c := range conf.MDNSZones {
		c.run(mzones, nil)
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
				Res:            res,
				ShutdownServer: cancel,
			}
			s.Serve(ctx)
			wg.Done()
		}()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Fatalf("cannot enumerate interfaces: %v", err)
	}

	for _, ifi := range ifaces {
		if (ifi.Flags & net.FlagUp) == 0 {
			continue
		}

		addrs, err := ifi.Addrs()
		if err != nil {
			logger.Printf("unable to enumerate addresses for interface %s: %v; skipping", ifi.Name, err)
			continue
		}

		var firstGlobal4, firstLocal4, firstGlobal6, firstLocal6 net.IP

		for _, addr := range addrs {
			if addr.Network() != "ip+net" {
				continue
			}

			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				logger.Printf("bad interface address %s: %v; skipping", addr.String(), err)
				continue // this really should not happen
			}

			v4 := ip.To4() != nil

			if ip.IsGlobalUnicast() || ((ifi.Flags&net.FlagLoopback) != 0 && ip.IsLoopback()) {
				if v4 {
					if firstGlobal4 == nil {
						firstGlobal4 = ip
					}
				} else {
					if firstGlobal6 == nil {
						firstGlobal6 = ip
					}
				}
			}
			if (ifi.Flags&net.FlagLoopback) == 0 && ip.IsLinkLocalUnicast() {
				if v4 {
					if firstLocal4 == nil {
						firstLocal4 = ip
					}
				} else {
					if firstLocal6 == nil {
						firstLocal6 = ip
					}
				}
			}

			if conf.AutoListeners && (ip.IsLoopback() || ip.IsGlobalUnicast()) {
				udp, tcp := "udp", "tcp"
				if v4 {
					udp, tcp = "udp4", "tcp4"
				}
				address := net.JoinHostPort(ip.String(), "53")
				conf.Listeners = append(conf.Listeners,
					Listener{
						Network:       udp,
						Address:       address,
						InterfaceName: ifi.Name,
						VC:            false,
					},
					Listener{
						Network:       tcp,
						Address:       address,
						InterfaceName: ifi.Name,
						VC:            true,
					},
				)
			}
		}

		if (ifi.Flags & net.FlagMulticast) != 0 {
			if conf.AutoMDNSListeners {
				var ip4, ip6 net.IP

				if firstLocal4 != nil {
					ip4 = firstLocal4
				} else if firstGlobal4 != nil {
					ip4 = firstGlobal4
				}
				if firstLocal6 != nil {
					ip6 = firstLocal6
				} else if firstGlobal6 != nil {
					ip6 = firstGlobal6
				}

				if ip4 != nil {
					conf.MDNSListeners = append(conf.MDNSListeners,
						Listener{
							Network:       "udp4",
							Address:       net.JoinHostPort(ip4.String(), "5353"),
							InterfaceName: ifi.Name,
						},
					)
				}
				if ip6 != nil {
					conf.MDNSListeners = append(conf.MDNSListeners,
						Listener{
							Network:       "udp6",
							Address:       net.JoinHostPort(ip6.String(), "5353"),
							InterfaceName: ifi.Name,
						},
					)
				}
			}
		}
	}
	for _, l := range conf.Listeners {
		wg.Add(1)
		go func(l Listener) {
			l.run(ctx, wg, &conf, zones, res)
			wg.Done()
		}(l)
	}
	for _, l := range conf.MDNSListeners {
		wg.Add(1)
		go func(l Listener) {
			l.runMDNS(ctx, zones)
			wg.Done()
		}(l)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	select {
	case sig := <-sigc:
		cancel()
		logger.Printf("shutting down on %v", sig)
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
