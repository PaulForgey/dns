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
	PrimaryNetwork   string            `json:",omitempty"` // secondary: udp/udp4/udp6,tcp/tcp4/tcp6 (defaults to udp)
	Incremental      bool              `json:",omitempty"` // secondary: use IXFR
	Class            dns.RRClass       `json:",omitempty"` // secondary: zone class (has invalid zero value, defaults to ANY)
	// XXX query, transfer, update ACL

	zone   *ns.Zone
	cancel context.CancelFunc
	ctx    context.Context
}

type REST struct {
	Addr string // if empty, listens globally on port 80. Probably not what you want
	// XXX authentication, source address restrictions
	// XXX TLS
}

type Conf struct {
	Zones    map[string]*Zone // zones
	Resolver string           // udp,udp4,udp6 empty for no recursive resolver
	REST     *REST            // REST server; omit or set to null to disable
	// XXX global server ACL
	// XXX mdns zone
}

var logStderr bool
var confFile string
var cache = resolver.NewRootZone()
var logger *log.Logger

func createZone(ctx context.Context, name string, conf *Zone) error {
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

func (conf *Zone) run(zones *ns.Zones) {
	switch conf.Type {
	case PrimaryType:
		conf.primaryZone(zones)

	case SecondaryType:
		conf.secondaryZone(zones)

	default:
		<-conf.ctx.Done()
	}

	conf.cancel()
	zones.Remove(conf.zone)
}

func makeListeners(ctx context.Context, wg *sync.WaitGroup, iface string, ip net.IP, zones *ns.Zones) {
	ip4 := (ip.To4() != nil)

	wg.Add(1)
	go func() {
		network := "udp"
		if ip4 {
			network = "udp4"
		}

		laddr := &net.UDPAddr{IP: ip, Port: 53}
		c, err := net.ListenUDP(network, laddr)
		if err != nil {
			logger.Println(err)
		} else {
			logger.Printf("%s: listening %s %v", iface, network, laddr)
			conn := dnsconn.NewConnection(c, network)
			conn.Interface = iface
			ns.Serve(ctx, logger, conn, zones)
			conn.Close()
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		network := "tcp"
		if ip4 {
			network = "tcp4"
		}

		laddr := &net.TCPAddr{IP: ip, Port: 53}
		c, err := net.ListenTCP(network, laddr)
		if err != nil {
			logger.Println(err)
		} else {
			logger.Printf("%s: listening %s %v", iface, network, laddr)
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
					wg.Add(1)
					go func() {
						conn := dnsconn.NewConnection(a, network)
						conn.Interface = iface
						ns.Serve(ctx, logger, conn, zones)
						conn.Close()
						wg.Done()
					}()
				}
			}
		}
		wg.Done()
	}()
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

	if conf.Resolver != "" {
		rc, err := net.ListenUDP(conf.Resolver, &net.UDPAddr{})
		if err != nil {
			logger.Fatalf("unable to create resolver socket: %v", err)
		}
		zones.R = resolver.NewResolver(zones, dnsconn.NewConnection(rc, conf.Resolver), true)
	}

	// load all data before running
	for name, c := range conf.Zones {
		err := createZone(ctx, name, c)
		if err != nil {
			logger.Fatalf("%s: cannot create zone: %v", name, err)
		}
		zones.Insert(c.zone, c.Type != SecondaryType) // secondary offline until loaded
	}

	for k, v := range conf.Zones {
		wg.Add(1)
		go func(name string, c *Zone) {
			c.run(zones)
			wg.Done()
		}(k, v)
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

		for _, addr := range addrs {
			if addr.Network() != "ip+net" {
				continue
			}

			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				logger.Printf("bad interface address %s: %v; skipping", addr.String(), err)
				continue // this really should not happen
			}

			if ip.IsLoopback() || ip.IsGlobalUnicast() {
				makeListeners(ctx, wg, ifi.Name, ip, zones)
			}
		}
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

	if zones.R != nil {
		zones.R.Close()
	}

	wg.Wait()
	logger.Printf("exiting: %v", ctx.Err())
}
