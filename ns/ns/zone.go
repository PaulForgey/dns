package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/resolver"
)

func (zone *Zone) create(ctx context.Context, conf *Conf, name string) error {
	if zone == nil {
		return fmt.Errorf("zone %s has no configuration body", name)
	}

	n, err := dns.NameWithString(name)
	if err != nil {
		return err
	}

	switch zone.Type {
	case PrimaryType, HintType:
		zone.zone = ns.NewZone(resolver.NewZone(n, zone.Type == HintType))
		if err := zone.load(); err != nil {
			return err
		}

	case SecondaryType:
		zone.zone = ns.NewZone(resolver.NewZone(n, false))
		zone.zone.Primary = zone.Primary

	case CacheType: // this is builtin and name is '.' regardless of what the configuration says
		zone.zone = ns.NewZone(cache)

	default:
		return fmt.Errorf("no such type %s", zone.Type)
	}

	zone.zone.AllowQuery = conf.Access(&zone.AllowQuery)
	zone.zone.AllowUpdate = conf.Access(&zone.AllowUpdate)
	zone.zone.AllowTransfer = conf.Access(&zone.AllowTransfer)
	zone.zone.AllowNotify = conf.Access(&zone.AllowNotify)
	zone.conf = conf
	zone.ctx, zone.cancel = context.WithCancel(ctx)
	return nil
}

func (zone *Zone) load() error {
	if zone.DbFile == "" {
		return nil
	}
	z := zone.zone

	c, err := dns.NewTextFileReader(zone.DbFile, z.Name())
	if err != nil {
		return err
	}

	err = z.Decode("", true, c)
	if err != nil {
		return err
	}

	for iface, dbfile := range zone.InterfaceDbFiles {
		// if this is a secondary zone, interface specific records will be lost on first successful transfer
		c, err := dns.NewTextFileReader(dbfile, z.Name())
		if err != nil {
			return fmt.Errorf("interface %s: %w", iface, err)
		}
		err = z.Decode(iface, true, c)
		if err != nil {
			return err
		}
		logger.Printf("%s:%v: loaded from %s", iface, z.Name(), dbfile)
	}

	logger.Printf("%v: loaded from %s", z.Name(), zone.DbFile)
	return nil
}

func (zone *Zone) save() error {
	if zone.DbFile == "" {
		return nil
	}

	z := zone.zone
	files := make(map[string]string)
	files[""] = zone.DbFile
	for key, dbfile := range zone.InterfaceDbFiles {
		files[key] = dbfile
	}

	for key, dbfile := range files {
		tmpfile := fmt.Sprintf("%s-%d", dbfile, os.Getpid())
		out, err := os.Create(tmpfile)
		if err != nil {
			logger.Printf("%v: failed to create output db file %s: %v", z.Name(), tmpfile, err)
			continue
		}

		bw := bufio.NewWriter(out)
		w := dns.NewTextWriter(bw)

		err = z.Encode(key, w)
		if err != nil {
			out.Close()
			return err // more than a warning, something is wrong
		}
		if err := bw.Flush(); err != nil {
			out.Close()
			return err
		}
		out.Close()

		err = os.Rename(tmpfile, dbfile)
		if err != nil {
			logger.Printf(
				"%v: failed to rename %s->%s: %v", z.Name(), tmpfile, dbfile, err)
			continue
		}
	}
	return nil
}

func (zone *Zone) run(zones *ns.Zones, res *resolver.Resolver) {
	zone.wg.Add(1)
	go func() {
		switch zone.Type {
		case PrimaryType:
			zone.primaryZone(zones, res)

		case SecondaryType:
			zone.secondaryZone(zones, res)

		default:
			<-zone.ctx.Done()
		}

		zones.Remove(zone.zone)
		zone.cancel()
		zone.wg.Done()
	}()
}

func (zone *Zone) wait() {
	zone.wg.Wait()
}
