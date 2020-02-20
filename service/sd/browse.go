package main

import (
	"context"
	"os"
	"os/signal"

	"tessier-ashpool.net/dns"
)

var browseUsage = "browse [service protocol]"

func browse(args []string) {
	var service, protocol string
	rrclass := dns.INClass

	if len(args) >= 2 {
		service, protocol = args[0], args[1]
	}

	if len(args) > 2 {
		if err := rrclass.Set(args[2]); err != nil {
			exitError(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan os.Signal, 1)
	go func() {
		<-ch
		cancel()
	}()
	signal.Notify(ch, os.Interrupt)

	err := sd.Browse(ctx, rrclass, service, protocol, printAnswers)
	exitError(err)
}
