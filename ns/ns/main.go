package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"os"
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
	DbFile           string
	InterfaceDbFiles map[string]string // primary: interface specific records
	Primary          string            // secondary: primary server to transfer from
	Incremental      bool              // secondary: use IXFR
	// XXX query, transfer, update ACL
}

type Conf struct {
	Zones    map[string]Zone // zones
	Resolver string          // udp,udp4,udp6 empty for no recursive resolver
	// XXX global server ACL
	// XXX mdns zone
}

var logStderr bool
var confFile string
var cache = resolver.NewRootZone()
var logger *log.Logger

func loadZone(zone *resolver.Zone, conf *Zone) error {
	c, err := dns.NewTextFileReader(conf.DbFile, zone.Name)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", conf.DbFile, err)
	}
	err = zone.Decode("", false, c)
	if err != nil {
		return err
	}
	for iface, dbfile := range conf.InterfaceDbFiles {
		c, err := dns.NewTextFileReader(dbfile, zone.Name)
		if err != nil {
			return fmt.Errorf("cannot open %s for interface %s: %w", dbfile, iface, err)
		}
		err = zone.Decode(iface, false, c)
		if err != nil {
			return err
		}
		logger.Printf("loaded zone %s:%v from %s", iface, zone.Name, dbfile)
	}

	logger.Printf("loaded zone %v from %s", zone.Name, conf.DbFile)
	return nil
}

func createZone(name string, conf *Zone) (*ns.Zone, error) {
	var zone *resolver.Zone
	n, err := dns.NameWithString(name)
	if err != nil {
		return nil, err
	}

	switch conf.Type {
	case PrimaryType, HintType:
		zone = resolver.NewZone(n)
		zone.Hint = (conf.Type == HintType)
		if err := loadZone(zone, conf); err != nil {
			return nil, fmt.Errorf("cannot load zone %s: %w", name, err)
		}
	case SecondaryType:
		// XXX
		return nil, fmt.Errorf("%s type not yet supported", conf.Type)
	case CacheType: // this is builtin and name is '.' regardless of what the configuration says
		zone = cache
	}

	return &ns.Zone{Zone: zone}, nil
}

func makeListeners(ctx context.Context, wg *sync.WaitGroup, iface string, ip net.IP, zones *ns.Zones) {
	wg.Add(1)
	go func() {
		laddr := &net.UDPAddr{IP: ip, Port: 53}
		c, err := net.ListenUDP("udp", laddr)
		if err != nil {
			logger.Printf("cannot create udp listener on %v: %v", ip, err)
		} else {
			logger.Printf("%s: listening udp %v", iface, laddr)
			conn := dnsconn.NewConnection(c, "udp", dnsconn.MinMessageSize)
			conn.Interface = iface
			ns.Serve(ctx, logger, conn, zones)
			conn.Close()
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		laddr := &net.TCPAddr{IP: ip, Port: 53}
		c, err := net.ListenTCP("tcp", laddr)
		if err != nil {
			logger.Printf("cannot create tcp listener on %v: %v", ip, err)
		} else {
			logger.Printf("%s: listening tcp %v", iface, laddr)
			for {
				a, err := c.Accept()
				if err != nil {
					logger.Printf("tcp listener exiting: %v", err)
					break
				} else {
					wg.Add(1)
					go func() {
						conn := dnsconn.NewConnection(a, "tcp", dnsconn.MaxMessageSize)
						conn.Interface = iface
						ns.Serve(ctx, logger, conn, zones)
						conn.Close()
						wg.Done()
					}()
				}
			}
		}
		c.Close()
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
		logger = log.New(os.Stderr, "ns", log.LstdFlags)
	} else {
		logger, err = syslog.NewLogger(syslog.LOG_NOTICE|syslog.LOG_DAEMON, log.LstdFlags)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to connect to syslog: %v", err)
			os.Exit(1)
		}
	}

	c, err := os.Open(confFile)
	if err != nil {
		logger.Fatalf("unable to open configuration file %s: %v", confFile, err)
	}

	err = json.NewDecoder(c).Decode(&conf)
	c.Close()
	if err != nil {
		logger.Fatalf("unable to parse configuration file %s: %v", confFile, err)
	}

	zones := ns.NewZones()

	if conf.Resolver != "" {
		rc, err := net.ListenUDP(conf.Resolver, &net.UDPAddr{})
		if err != nil {
			logger.Fatalf("unable to create resolver socket: %v", err)
		}
		zones.R = resolver.NewResolver(cache, dnsconn.NewConnection(rc, conf.Resolver, dnsconn.MinMessageSize), true)
	}

	for k, v := range conf.Zones {
		zone, err := createZone(k, &v)
		if err != nil {
			logger.Fatalf("cannot load zone %s: %v", k, err)
		}
		zones.Insert(zone)
	}

	ctx := context.Background() // XXX can make this cancelable for a clean shutdown
	wg := &sync.WaitGroup{}

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

	wg.Wait()
	logger.Printf("exiting: %v", err)
}
