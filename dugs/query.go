package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func printRecords(rrsets resolver.IfaceRRSets) error {
	for iface, records := range rrsets {
		for _, r := range records {
			fmt.Printf("%s: %v\n", iface, r)
		}
	}
	fmt.Println()
	return nil
}

func query(r *resolver.MResolver, questions []dns.Question) {
	if oneshot {
		rrsets, err := r.QueryOne(context.Background(), questions)
		if err != nil {
			exitError(err)
		}

		printRecords(rrsets)
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		go func() {
			<-c
			cancel()
		}()

		err := r.Query(ctx, questions, printRecords)
		cancel()

		if err != nil {
			exitError(err)
		}
	}
}
