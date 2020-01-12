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
	// XXX query, transfer, update ACL

	zone   *ns.Zone
	cancel context.CancelFunc
	ctx    context.Context
	wg     sync.WaitGroup
}

type REST struct {
	Addr string // if empty, listens globally on port 80. Probably not what you want
	// XXX authentication, source address restrictions
	// XXX TLS
}

type Listener struct {
	Network string // network name, e.g. tcp, udp4
	Address string // network address, e.g. 127.0.0.1:53
	Name    string // optional interface name for interface specific records (does not have to match actual interface)
	VC      bool   // network is not packet based, that is, it needs to Accept() connections
}

type Conf struct {
	sync.Mutex

	Zones         map[string]*Zone // zones
	Resolver      string           // udp,udp4,udp6 empty for no recursive resolver
	REST          *REST            // REST server; omit or set to null to disable
	Listeners     []Listener       // additional listeners, or a specific set if opting out of automatic interface discovery
	AutoListeners bool             // true to automatically discover all interfaces to listen on

	// XXX global server ACL
	// XXX mdns zone
}

var logStderr bool
var confFile string
var cache = resolver.NewRootZone()
var logger *log.Logger

func (conf *Zone) create(ctx context.Context, name string) error {
	if conf == nil {
		return fmt.Errorf("zone %s has no configuration body", name)
	}

	n, err := dns.NameWithString(name)
	if err != nil {
		return err
	}

	switch conf.Type {
	case PrimaryType, HintType:
		conf.zone = ns.NewZone(resolver.NewZone(n, conf.Type == HintType))
		if err := conf.load(); err != nil {
			return err
		}

	case SecondaryType:
		conf.zone = ns.NewZone(resolver.NewZone(n, false))
		conf.zone.Primary = conf.Primary

	case CacheType: // this is builtin and name is '.' regardless of what the configuration says
		conf.zone = ns.NewZone(cache)

	default:
		return fmt.Errorf("no such type %s", conf.Type)
	}

	conf.ctx, conf.cancel = context.WithCancel(ctx)
	return nil
}

func (conf *Zone) load() error {
	if conf.DbFile == "" {
		return nil
	}
	zone := conf.zone

	c, err := dns.NewTextFileReader(conf.DbFile, zone.Name())
	if err != nil {
		return err
	}

	err = zone.Decode("", false, c)
	if err != nil {
		return err
	}

	for iface, dbfile := range conf.InterfaceDbFiles {
		// if this is a secondary zone, interface specific records will be lost on first successful transfer
		c, err := dns.NewTextFileReader(dbfile, zone.Name())
		if err != nil {
			return fmt.Errorf("interface %s: %w", iface, err)
		}
		err = zone.Decode(iface, false, c)
		if err != nil {
			return err
		}
		logger.Printf("%s:%v: loaded from %s", iface, zone.Name(), dbfile)
	}

	logger.Printf("%v: loaded from %s", zone.Name(), conf.DbFile)
	return nil
}

func (conf *Zone) run(zones *ns.Zones, res *resolver.Resolver) {
	conf.wg.Add(1)
	go func() {
		switch conf.Type {
		case PrimaryType:
			conf.primaryZone(zones, res)

		case SecondaryType:
			conf.secondaryZone(zones, res)

		default:
			<-conf.ctx.Done()
		}

		zones.Remove(conf.zone)
		conf.cancel()
		conf.wg.Done()
	}()
}

func (conf *Zone) wait() {
	conf.wg.Wait()
}

func (l *Listener) run(ctx context.Context, wg *sync.WaitGroup, zones *ns.Zones, res *resolver.Resolver) {
	if l.VC {
		c, err := net.Listen(l.Network, l.Address)
		if err != nil {
			logger.Println(err)
			return
		}

		logger.Printf("%s: listening %s %v", l.Name, l.Network, l.Address)
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
					conn := dnsconn.NewConnection(a, l.Network)
					conn.Interface = l.Name
					s := ns.NewServer(logger, conn, zones, res)
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
		var nc net.Conn
		if udp, ok := c.(*net.UDPConn); ok {
			nc = udp
		} else if unix, ok := c.(*net.UnixConn); ok {
			nc = unix
		} else {
			c.Close()
			logger.Printf("%s: network type %s is not udp or unix", l.Name, l.Network)
		}

		if nc != nil {
			logger.Printf("%s: listening %s %v", l.Name, l.Network, l.Address)
			conn := dnsconn.NewConnection(nc, l.Network)
			conn.Interface = l.Name
			s := ns.NewServer(logger, conn, zones, res)
			s.Serve(ctx)
			conn.Close()
		}
	}
}

func main() {
	var err error
	var conf Conf

	flag.BoolVar(&logStderr, "stderr", false, "log using stderr")
	flag.StringVar(&confFile, "conf", "ns.json", "configuration file location")

	flag.Parse()

	if logStderr {
		logger = log.New(os.Stderr, "ns:", log.LstdFlags)
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
	var res *resolver.Resolver

	if conf.Resolver != "" {
		rc, err := net.ListenUDP(conf.Resolver, &net.UDPAddr{})
		if err != nil {
			logger.Fatalf("unable to create resolver socket: %v", err)
		}
		res = resolver.NewResolver(zones, dnsconn.NewConnection(rc, conf.Resolver), true)
	}

	// load all data before running
	for name, c := range conf.Zones {
		err := c.create(ctx, name)
		if err != nil {
			logger.Fatalf("%s: cannot create zone: %v", name, err)
		}
		zones.Insert(c.zone, c.Type != SecondaryType) // secondary offline until loaded
	}

	for _, c := range conf.Zones {
		c.run(zones, res)
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

	if conf.AutoListeners {
		for _, ifi := range ifaces {
			if (ifi.Flags & net.FlagUp) == 0 {
				continue
			}

			addrs, err := ifi.Addrs()
			if err != nil {
				logger.Printf("unable to enumerate addresses for interface %s: %v; skipping", ifi.Name, err)
				continue
			}

			for _, addr := range addrs {
				if addr.Network() != "ip+net" {
					continue
				}

				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					logger.Printf("bad interface address %s: %v; skipping", addr.String(), err)
					continue // this really should not happen
				}

				if !(ip.IsLoopback() || ip.IsGlobalUnicast()) {
					continue
				}

				udp, tcp := "udp", "tcp"
				if ip.To4() != nil {
					udp, tcp = "udp4", "tcp4"
				}
				conf.Listeners = append(conf.Listeners,
					Listener{
						Network: udp,
						Address: net.JoinHostPort(ip.String(), "53"),
						Name:    ifi.Name,
						VC:      false,
					},
					Listener{
						Network: tcp,
						Address: net.JoinHostPort(ip.String(), "53"),
						Name:    ifi.Name,
						VC:      true,
					},
				)
			}
		}
	}
	for _, l := range conf.Listeners {
		wg.Add(1)
		go func(l Listener) {
			l.run(ctx, wg, zones, res)
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
