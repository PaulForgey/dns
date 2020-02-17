package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func query(r *resolver.MResolver, questions []dns.Question) {
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
