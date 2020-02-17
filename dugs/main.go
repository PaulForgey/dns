package main

import (
	"flag"
	"fmt"
	"os"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

var network = "unix"
var host = "/var/run/mDNS/mDNS-socket"
var rrtype = dns.AnyType
var rrclass = dns.INClass
var qu = false
var oneshot = false
var updates string

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
	flag.StringVar(&updates, "updates", updates, "file for updates (- for stdin)")

	flag.Parse()
	args := flag.Args()

	r, err := resolver.NewMResolverClient(network, host)
	if err != nil {
		exitError(err)
	}
	defer r.Close()

	questions := make([]dns.Question, len(args))

	for i, arg := range args {
		name, err := dns.NameWithString(arg)
		if err != nil {
			exitErrorf("cannot parse '%s' as DNS name: %v", arg, err)
		}
		questions[i] = dns.NewMDNSQuestion(name, rrtype, rrclass, qu)
	}

	if updates != "" {
		update(r)
	} else {
		query(r, questions)
	}
}
