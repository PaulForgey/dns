package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime/trace"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var debug bool
var network = "udp"
var host string
var rrtype = dns.AnyType
var rrclass = dns.INClass
var rd = true
var serial uint
var updates string
var x bool
var loop int
var traceFile string
var stats bool

func exitError(msg interface{}) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], msg)
	os.Exit(1)
}

func exitErrorf(s string, args ...interface{}) {
	exitError(fmt.Sprintf(s, args...))
}

func main() {
	flag.BoolVar(&debug, "debug", debug, "show queries and answers")
	flag.StringVar(&network, "network", network, "specify network of connection")
	flag.StringVar(&host, "host", host, "specify host of connection (omit to be rescursive root)")
	flag.Var(&rrtype, "type", "type")
	flag.Var(&rrclass, "class", "class")
	flag.BoolVar(&rd, "rd", true, "send recursive queries to -host")
	flag.UintVar(&serial, "serial", serial, "if -type=ixfr, serial to use in SOA")
	flag.StringVar(&updates, "updates", updates, "file to send ddns updates from (- for stdin)")
	flag.BoolVar(&x, "x", x, "convert name to reverse IP in arpa zone")
	flag.IntVar(&loop, "loop", loop, "(debug) run query multiple times for subsequent cache hit")
	flag.StringVar(&traceFile, "trace", traceFile, "trace output file")
	flag.BoolVar(&stats, "stats", stats, "dump cache stats")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] name\n", os.Args[0])
		os.Exit(2)
	}

	if traceFile != "" {
		f, err := os.Create(traceFile)
		if err != nil {
			exitErrorf("cannot create trace file: %v", err)
		}
		if err := trace.Start(f); err != nil {
			exitErrorf("cannot start trace: %v", err)
		}
		defer func() {
			trace.Stop()
			f.Close()
		}()
	}

	var name dns.Name
	var err error

	if x {
		var ip net.IP
		ip = net.ParseIP(args[0])
		if ip == nil {
			exitErrorf("cannot parse '%s' as ip address", args[0])
		}
		name = resolver.ArpaName(ip)
	} else {
		name, err = dns.NameWithString(args[0])
		if err != nil {
			exitErrorf("cannot parse name '%s': %v", args[0], err)
		}
	}

	var r *resolver.Resolver
	var cache resolver.Authority
	if host != "" {
		cache = resolver.EmptyCache
		r, err = resolver.NewResolverClient(cache, network, host, nil, rd)
	} else {
		conn, err := net.ListenUDP(network, nil)
		if err != nil {
			exitErrorf("cannot create resolver socket: %v", err)
		}
		cache = resolver.RootCache
		r = resolver.NewResolver(cache, dnsconn.NewConn(conn, network, ""), true)
	}
	if err != nil {
		exitErrorf("cannot create resolver: %v", err)
	}

	if debug {
		textCodec := dns.NewTextWriter(os.Stdout)
		r.Debug(textCodec)
	}

	for i := 0; i <= loop; i++ {
		if updates != "" {
			update(name, r)
		} else {
			switch rrtype {
			case dns.AXFRType, dns.IXFRType:
				xfer(name, r)

			default:
				query(name, r)
			}
		}
	}

	if stats {
		json.NewEncoder(os.Stdout).Encode(cache.Find(nil).Stats())
	}
}
