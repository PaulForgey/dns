package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var debug bool
var network string
var host string
var rrtype = dns.AnyType
var rrclass = dns.INClass
var rd = true

func exitError(msg interface{}) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], msg)
	os.Exit(1)
}

func exitErrorF(s string, args ...interface{}) {
	exitError(fmt.Sprintf(s, args...))
}

func main() {
	flag.BoolVar(&debug, "debug", false, "show queries and answers")
	flag.StringVar(&network, "network", "udp", "specify network of connection")
	flag.StringVar(&host, "host", "", "specify host of connection (omit to be rescursive root)")
	flag.Var(&rrtype, "type", "type")
	flag.Var(&rrclass, "class", "class")
	flag.BoolVar(&rd, "rd", true, "send recursive queries to -host")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] name\n", os.Args[0])
		os.Exit(2)
	}

	name, err := dns.NameWithString(args[0])
	if err != nil {
		exitErrorF("cannot parse name '%s': %v", name, err)
	}

	var r *resolver.Resolver
	if host != "" {
		r, err = resolver.NewResolverClient(resolver.EmptyCache, network, host, nil, rd)
	} else {
		conn, err := net.ListenUDP(network, nil)
		if err != nil {
			exitErrorF("cannot create resolver socket: %v", err)
		}
		r = resolver.NewResolver(
			resolver.RootCache,
			dnsconn.NewConnection(conn, network),
			true,
		)
	}
	if err != nil {
		exitErrorF("cannot create resolver: %v", err)
	}

	if debug {
		textCodec := dns.NewTextWriter(os.Stdout)
		r.Debug(textCodec)
	}

	records, err := r.Resolve(context.Background(), "", name, rrtype, rrclass)
	if err != nil {
		exitError(err)
	}

	if debug {
		fmt.Printf("\n;; answers:\n")
	}

	for _, record := range records {
		fmt.Println(record)
	}
}
