package main

import (
	"context"
	"fmt"
	"net"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

const lookupUsage = "lookup name [type [class]]"
const addrUsage = "addr ip-address"
const hostUsage = "host hostname [network]"

func printAnswers(answers resolver.IfaceRRSets) error {
	for iface, records := range answers {
		for _, r := range records {
			fmt.Printf("%s: %v\n", iface, r)
		}
	}
	fmt.Println()
	return nil
}

func lookup(args []string) {
	if len(args) < 1 {
		exitUsage(lookupUsage)
	}

	rrtype := dns.AnyType
	rrclass := dns.INClass

	if len(args) > 1 {
		if err := rrtype.Set(args[1]); err != nil {
			exitError(err)
		}
	}
	if len(args) > 2 {
		if err := rrclass.Set(args[2]); err != nil {
			exitError(err)
		}
	}

	answers, err := sd.Lookup(context.Background(), args[0], rrtype, rrclass)
	if err != nil {
		exitError(err)
	}

	printAnswers(answers)
}

func lookupAddr(args []string) {
	if len(args) < 1 {
		exitUsage(addrUsage)
	}

	ip := net.ParseIP(args[0])
	if ip == nil {
		exitErrorf("cannot parse '%s' as IP address", args[0])
	}

	hosts, err := sd.LookupAddr(context.Background(), ip)
	if err != nil {
		exitError(err)
	}

	for _, h := range hosts {
		fmt.Println(h)
	}
}

func lookupHost(args []string) {
	if len(args) < 1 {
		exitUsage(hostUsage)
	}
	network := "ip"
	if len(args) > 1 {
		network = args[1]
	}

	addrs, err := sd.LookupHost(context.Background(), network, args[0])
	if err != nil {
		exitError(err)
	}

	for _, addr := range addrs {
		fmt.Println(addr)
	}
}
