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
	Type        ZoneType
	DbFile      string
	Primary     string // secondary: primary server to transfer from
	Incremental bool   // secondary: use IXFR
	// XXX query, transfer, update ACL
}

type ListenerConfig struct {
	UDPNetwork string // udp,udp4,udp6 or empty to not listen
	TCPNetwork string // tcp,tcp4,tcp6 or empty to not listen
}

type Conf struct {
	Zones    map[string]Zone // zones
	Listener ListenerConfig  // external daemon and queries
	// XXX global server ACL
	// XXX mdns zone
}

var logStderr bool
var confFile string
var udpListener *dnsconn.Connection
var cache = resolver.NewRootZone()
var logger *log.Logger

func loadZone(zone *resolver.Zone, dbfile string) error {
	c, err := dns.NewTextFileReader(dbfile, zone.Name)
	if err != nil {
		return err
	}
	// XXX we could somewhat easily support interface specific zone records
	err = zone.Decode("", false, c)
	if err != nil {
		return err
	}

	logger.Printf("loaded zone %v from %s", zone.Name, dbfile)
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
		if err := loadZone(zone, conf.DbFile); err != nil {
			return nil, fmt.Errorf("cannot load zone %s from db file %s: %w", name, conf.DbFile, err)
		}
	case SecondaryType:
		// XXX
		return nil, fmt.Errorf("%s type not yet supported", conf.Type)
	case CacheType: // this is builtin and name is '.' regardless of what the configuration says
		zone = cache
	}

	return &ns.Zone{Zone: zone}, nil
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

	ctx := context.Background() // XXX can make this cancelable for a clean shutdown

	var rr *resolver.Resolver
	if conf.Listener.UDPNetwork != "" {
		network := conf.Listener.UDPNetwork
		conn, err := net.ListenUDP(network, &net.UDPAddr{Port: 53})
		if err != nil {
			logger.Fatalf("unable to create udp listener: %v", err)
		}
		udpListener = dnsconn.NewConnection(conn, network, dnsconn.MinMessageSize)
		rr = resolver.NewResolver(cache, udpListener, true)
	}

	zones := ns.NewZones()
	for k, v := range conf.Zones {
		zone, err := createZone(k, &v)
		if err != nil {
			logger.Fatalf("cannot load zone %s: %v", k, err)
		}
		if zone.Hint {
			zone.R = rr
		}
		zones.Insert(zone)
	}

	wg := &sync.WaitGroup{}
	if conf.Listener.TCPNetwork != "" {
		network := conf.Listener.TCPNetwork
		conn, err := net.ListenTCP(network, &net.TCPAddr{Port: 53})
		if err != nil {
			logger.Fatalf("unable to create tcp listener: %v", err)
		}
		logger.Printf("answering TCP queries")
		wg.Add(1)
		go func() {
			for {
				a, err := conn.Accept()
				if err != nil {
					logger.Printf("TCP listener: %v", err)
					break
				}
				wg.Add(1)
				go func() {
					tc := dnsconn.NewConnection(a, network, dnsconn.MaxMessageSize)
					ns.Serve(ctx, logger, tc, zones)
					tc.Close()
					wg.Done()
				}()
			}
			wg.Done()
		}()
	}

	if udpListener != nil {
		logger.Printf("answering UDP queries")
		err = ns.Serve(ctx, logger, udpListener, zones)
	}
	wg.Wait()
	logger.Printf("exiting: %v", err)
}
