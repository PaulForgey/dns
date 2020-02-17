package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func printRecords(iface string, records []*dns.Record) {
	fmt.Printf("; iface=%s\n", iface)
	if len(records) > 0 {
		for _, r := range records {
			fmt.Println(r)
		}
	} else {
		fmt.Println("; none")
	}
	fmt.Println()
}

func query(r *resolver.MResolver, questions []dns.Question) {
	if oneshot {
		rrsets, err := r.QueryOne(context.Background(), questions)
		if err != nil {
			exitError(err)
		}

		for iface, records := range rrsets {
			printRecords(iface, records)
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
			printRecords(iface, records)
			return nil
		})

		if err != nil {
			exitError(err)
		}
	}
}
