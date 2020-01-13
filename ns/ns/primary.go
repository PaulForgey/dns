package main

import (
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func (zone *Zone) primaryZone(zones *ns.Zones, res *resolver.Resolver) {
	var err error

	ctx := zone.ctx
	z := zone.zone

	s := ns.NewServer(logger, nil, zones, res, zone.conf.Access(&zone.conf.AllowRecursion))

	for err == nil {
		err = s.SendNotify(ctx, z)
		if err != nil {
			logger.Printf("%v: failed to send NOTIFY: %v", z.Name(), err)
			err = nil // just a warning
		}

		select {
		case <-ctx.Done():
			err = ctx.Err()

		case <-z.ReloadC():
			err = zone.load()
		}
	}
	logger.Printf("%v: zone routine exiting: %v", z.Name(), err)
}
