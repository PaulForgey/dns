package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

func update(name dns.Name, r *resolver.Resolver) {
	var err error

	file := os.Stdin
	if updates != "-" {
		file, err = os.Open(updates)
		if err != nil {
			exitError(err)
		}
		defer file.Close()
	}

	c := dns.NewTextReader(file, name)
	msg := &dns.Message{
		Opcode:    dns.Update,
		Questions: []dns.Question{dns.NewDNSQuestion(name, dns.SOAType, rrclass)},
	}

	for {
		rr := &dns.Records{}
		if err := c.Decode(rr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			exitError(err)
		}
		switch strings.ToLower(rr.Annotation) {
		case "prereq":
			msg.Answers = rr.Records

		case "update":
			msg.Authority = rr.Records
			_, err := r.Transact(context.Background(), nil, msg)
			if err != nil {
				exitError(err)
			}
			msg.Answers = nil // clear optional prereq section for next update

		default:
			exitErrorf("unknown update section type %s", rr.Annotation)
		}
	}
}
