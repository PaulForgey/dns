package main

import (
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func (zone *Zone) primaryZone(zones *ns.Zones, res *resolver.Resolver) {
	var err error

	ctx := zone.ctx
	z := zone.zone

	s := ns.NewServer(logger, nil, zones, res, ns.AllAccess)
	notify := &Delay{}

	s.SendNotify(ctx, z)

	for err == nil {
		select {
		case <-ctx.Done():
			err = ctx.Err()

		case <-z.ReloadC():
			err = zone.load()
			if err == nil {
				notify.Start()
			}

		case <-z.NotifyC():
			notify.Start()

		case <-notify.Fire():
			notify.Reset()
			if zone.Type == PrimaryType {
				s.SendNotify(ctx, z)
			}
		}
	}
	notify.Stop()
	logger.Printf("%v: zone routine exiting: %v", z.Name(), err)
}
