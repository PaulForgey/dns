package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func printRecords(rrsets resolver.IfaceRRSets) {
	for iface, records := range rrsets {
		if iface == "" && len(records) == 0 {
			continue
		}
		fmt.Printf("; iface=%s\n", iface)
		if len(records) > 0 {
			for _, r := range records {
				fmt.Println(r)
			}
		} else {
			fmt.Println("; none")
		}
	}
	fmt.Println()
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

		err := r.Query(ctx, questions, func(rrsets resolver.IfaceRRSets) error {
			printRecords(rrsets)
			return nil
		})
		cancel()

		if err != nil {
			exitError(err)
		}
	}
}
