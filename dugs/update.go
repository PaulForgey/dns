package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func update(r *resolver.MResolver) {
	var err error

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)

	go func() {
		<-ch
		cancel()
	}()

	file := os.Stdin
	if updates != "-" {
		file, err = os.Open(updates)
		if err != nil {
			exitError(err)
		}
		defer file.Close()
	}

	names := make(resolver.OwnerNames)
	c := dns.NewTextReader(file, nil)
	for {
		rr := &dns.Records{}
		if err := c.Decode(rr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			exitError(err)
		}
		err = names.Enter(nil, rr.Annotation, rr.Records)
		if err != nil {
			exitError(err)
		}
	}

	err = r.Announce(ctx, names)
	exitError(err)
}
