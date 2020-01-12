package main

import (
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func (conf *Zone) primaryZone(zones *ns.Zones, res *resolver.Resolver) {
	var err error

	ctx := conf.ctx
	zone := conf.zone

	s := ns.NewServer(logger, nil, zones, res)

	for err == nil {
		err = s.SendNotify(ctx, zone)
		if err != nil {
			logger.Printf("%v: failed to send NOTIFY: %v", zone.Name(), err)
			err = nil // just a warning
		}

		select {
		case <-ctx.Done():
			err = ctx.Err()

		case <-zone.C:
			err = conf.load()
		}
	}
	logger.Printf("%v: zone routine exiting: %v", zone.Name(), err)
}
