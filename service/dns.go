package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/resolver"
)

// unicast (aka "normal") dns and ddns

const qtimeout = 5 * time.Second

type dnsService struct {
	resolver *resolver.Resolver
}

func (d *dnsService) Lookup(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
) (resolver.IfaceRRSets, error) {
	var err error
	var records []*dns.Record

	records, err = d.resolver.Resolve(ctx, "", name, rrtype, rrclass)
	if err != nil && !errors.Is(err, dns.NXDomain) {
		return nil, err
	}

	result := make(resolver.IfaceRRSets)
	if len(records) > 0 {
		result[""] = records
	}

	return result, err
}

// 'Exclusive' owners will include a prereq for no other rrsets of that name
func (d *dnsService) Announce(
	ctx context.Context,
	zone dns.Name,
	names resolver.OwnerNames,
) error {
	msg := &dns.Message{Opcode: dns.Update}

	for _, owner := range names {
		if msg.Questions == nil {
			msg.Questions = []dns.Question{
				dns.NewDNSQuestion(zone, dns.SOAType, owner.RRClass),
			}
		} else if msg.Questions[0].Class() == owner.RRClass {
			return fmt.Errorf("%w: inconsistent class records in zone", dns.FormError)
		}

		update := dns.Copy(owner.RRSets.AllRecords())
		msg.Authority = append(msg.Authority, update...)

		if owner.Exclusive {
			var prereq []*dns.Record

			for _, r := range update {
				pr := &dns.Record{
					H: dns.NewHeader(r.Name(), r.Type(), dns.NoneClass, 0),
					D: nil,
				}
				found := false
				for _, a := range prereq {
					if a.Equal(pr) {
						found = true
						break
					}
				}
				if !found {
					prereq = append(prereq, r)
				}
			}
			msg.Answers = append(msg.Answers, prereq...)
		}
	}

	tctx, cancel := context.WithTimeout(ctx, qtimeout)
	_, err := d.resolver.Transact(tctx, nil, msg)
	cancel()
	if errors.Is(err, dns.YXRRSet) {
		// try again with a prereq set to what we are trying to update
		msg.Answers = dns.Copy(msg.Authority)
		for _, a := range msg.Answers {
			a.H.SetTTL(0)
		}
		_, err = d.resolver.Transact(ctx, nil, msg)
	}
	if err != nil {
		return err
	}

	<-ctx.Done()
	err = ctx.Err()

	msg.Answers = nil
	msg.Authority = dns.Copy(msg.Authority) // don't biff up the original records
	for _, a := range msg.Authority {
		a.H = dns.NewHeader(a.Name(), a.Type(), dns.NoneClass, 0)
	}

	tctx, cancel = context.WithTimeout(context.Background(), qtimeout)
	d.resolver.Transact(tctx, nil, msg) // best effort
	cancel()

	return err
}

// for normal dns, Browse and Lookup do the same thing
func (d *dnsService) Browse(
	ctx context.Context,
	name dns.Name,
	rrtype dns.RRType,
	rrclass dns.RRClass,
	result func(resolver.IfaceRRSets) error,
) error {
	answers, err := d.Lookup(ctx, name, rrtype, rrclass)
	if err == nil {
		err = result(answers)
		<-ctx.Done()
		err = ctx.Err()
	}
	return err
}

func (d *dnsService) Self() (dns.Name, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return dns.NameWithString(hostname)
}
