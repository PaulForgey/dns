package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var network = "unix"
var host = "/var/run/mDNS"
var rrtype = dns.AnyType
var rrclass = dns.INClass
var qu = false
var oneshot = false

func exitError(msg interface{}) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], msg)
	os.Exit(1)
}

func exitErrorf(s string, args ...interface{}) {
	exitError(fmt.Sprintf(s, args...))
}

func main() {
	flag.StringVar(&network, "network", network, "specify IPC network")
	flag.StringVar(&host, "host", host, "specify IPC endpoint")
	flag.Var(&rrtype, "type", "type")
	flag.Var(&rrclass, "class", "class")
	flag.BoolVar(&qu, "qu", qu, "ask for unicast response")
	flag.BoolVar(&oneshot, "oneshot", oneshot, "one shot query")

	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] name [..name]\n", os.Args[0])
		os.Exit(2)
	}

	c, err := net.Dial(network, host)
	if err != nil {
		exitError(err)
	}
	conn := dnsconn.NewStreamConn(c, network, "")
	conn.MDNS()
	r := resolver.NewMResolver(conn)
	defer r.Close()

	questions := make([]dns.Question, len(args))

	for i, arg := range args {
		name, err := dns.NameWithString(arg)
		if err != nil {
			exitErrorf("cannot parse '%s' as DNS name: %v", arg, err)
		}
		questions[i] = dns.NewMDNSQuestion(name, rrtype, rrclass, qu)
	}

	if oneshot {
		records, err := r.QueryOne(context.Background(), questions)
		if err != nil {
			exitError(err)
		}

		for _, r := range records {
			fmt.Println(r)
		}
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		go func() {
			<-c
			cancel()
		}()

		err := r.Query(ctx, questions, func(iface string, records []*dns.Record) error {
			fmt.Printf("; iface=%s\n", iface)
			if len(records) > 0 {
				for _, r := range records {
					fmt.Println(r)
				}
			} else {
				fmt.Println("; none")
			}
			fmt.Println()
			return nil
		})

		if err != nil {
			exitError(err)
		}
	}
}
