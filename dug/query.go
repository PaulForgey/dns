package main

import (
	"context"
	"fmt"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func query(name dns.Name, r *resolver.Resolver) {
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
