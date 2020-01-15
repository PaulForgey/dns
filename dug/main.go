package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/dnsconn"
	"tessier-ashpool.net/dns/resolver"
)

var debug bool
var network string
var host string
var rrtype = dns.AnyType
var rrclass = dns.INClass
var rd = true
var serial uint
var updates string

func exitError(msg interface{}) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[0], msg)
	os.Exit(1)
}

func exitErrorf(s string, args ...interface{}) {
	exitError(fmt.Sprintf(s, args...))
}

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
		Opcode: dns.Update,
		Questions: []*dns.Question{
			&dns.Question{
				QName:  name,
				QType:  dns.SOAType,
				QClass: rrclass,
			},
		},
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

func main() {
	flag.BoolVar(&debug, "debug", false, "show queries and answers")
	flag.StringVar(&network, "network", "udp", "specify network of connection")
	flag.StringVar(&host, "host", "", "specify host of connection (omit to be rescursive root)")
	flag.Var(&rrtype, "type", "type")
	flag.Var(&rrclass, "class", "class")
	flag.BoolVar(&rd, "rd", true, "send recursive queries to -host")
	flag.UintVar(&serial, "serial", 0, "if -type=ixfr, serial to use in SOA")
	flag.StringVar(&updates, "updates", "", "file to send ddns updates from (- for stdin)")

	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] name\n", os.Args[0])
		os.Exit(2)
	}

	name, err := dns.NameWithString(args[0])
	if err != nil {
		exitErrorf("cannot parse name '%s': %v", name, err)
	}

	var r *resolver.Resolver
	if host != "" {
		r, err = resolver.NewResolverClient(resolver.EmptyCache, network, host, nil, rd)
	} else {
		conn, err := net.ListenUDP(network, nil)
		if err != nil {
			exitErrorf("cannot create resolver socket: %v", err)
		}
		r = resolver.NewResolver(
			resolver.RootCache,
			dnsconn.NewConnection(conn, network),
			true,
		)
	}
	if err != nil {
		exitErrorf("cannot create resolver: %v", err)
	}

	if debug {
		textCodec := dns.NewTextWriter(os.Stdout)
		r.Debug(textCodec)
	}

	if updates != "" {
		update(name, r)
		return
	}

	switch rrtype {
	case dns.AXFRType, dns.IXFRType:
		msg := &dns.Message{
			Opcode: dns.StandardQuery,
			Questions: []*dns.Question{
				&dns.Question{
					QName:  name,
					QType:  rrtype,
					QClass: rrclass,
				},
			},
		}
		if rrtype == dns.IXFRType {
			msg.Authority = []*dns.Record{
				&dns.Record{
					H: dns.NewHeader(
						name,
						dns.SOAType,
						rrclass,
						0,
					),
					D: &dns.SOARecord{
						Serial: uint32(serial),
					},
				},
			}
		}
		msg, err = r.Transact(context.Background(), nil, msg)
		if err != nil {
			exitError(err)
		}

		if debug {
			fmt.Printf("\n;; transfer:\n")
		}

		if len(msg.Answers) > 0 {
			soa, _ := msg.Answers[0].D.(*dns.SOARecord)
			if soa != nil {
				fmt.Println(msg.Answers[0])
				msg.Answers = msg.Answers[1:]
			}

			var isoa *dns.SOARecord

			for {
				for _, record := range msg.Answers {
					fmt.Println(record)

					if record.Type() == dns.SOAType && soa != nil {
						switch rrtype {
						case dns.AXFRType:
							soa = nil

						case dns.IXFRType:
							if isoa == nil {
								isoa = record.D.(*dns.SOARecord)
								if isoa.Serial == soa.Serial {
									soa = nil
								}
							} else {
								isoa = nil
							}
						}
					}
				}
				if rrtype == dns.IXFRType && len(msg.Answers) == 0 {
					// hackish single answer SOA in response
					soa = nil
				}
				if soa == nil {
					break
				}
				msg, err = r.Receive(context.Background(), msg.ID)
				if err != nil {
					exitError(err)
				}
			}
		}

	default:
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
}
