package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/ns"
	"tessier-ashpool.net/dns/nsdb"
)

type updateLog struct {
	filename string
	file     *os.File
}

func newUpdateLog(filename string) *updateLog {
	return &updateLog{filename: filename}
}

func (l *updateLog) reset() {
	if l.file != nil {
		l.file.Close()
		os.Remove(l.filename)
		l.file = nil
	}
}

func (l *updateLog) open(reading bool) error {
	var err error

	if l.file != nil {
		l.file.Sync()
		l.file.Seek(0, 0)
	} else {
		if reading {
			if _, err := os.Stat(l.filename); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					err = nil
				}
				return err
			}
		}
		l.file, err = os.OpenFile(l.filename, os.O_APPEND|os.O_CREATE|os.O_RDWR|os.O_SYNC, 0644)
	}
	return err
}

func (l *updateLog) replay(z *ns.Zone) (bool, error) {
	z.UpdateLog = nil

	if l.file == nil {
		if err := l.open(true); err != nil {
			return false, err
		}
		if l.file == nil {
			// no log file to replay
			z.UpdateLog = l
			return false, nil
		}
	}

	_, err := l.file.Seek(0, 0)
	if err != nil {
		return false, err
	}

	updated := false
	r := dns.NewTextReader(bufio.NewReader(l.file), z.Name())
	records := &dns.Records{}
	for {
		if err := r.Decode(records); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return false, err
		}
		if u, err := z.Update(records.Annotation, nil, records.Records); err != nil {
			return false, err
		} else {
			updated = updated || u
		}
	}

	z.UpdateLog = l
	return updated, nil
}

func (l *updateLog) Update(key string, update []*dns.Record) error {
	if l.file == nil {
		if err := l.open(false); err != nil {
			return err
		}
	}
	s := &strings.Builder{}
	w := dns.NewTextWriter(s)
	if err := w.Encode(&dns.Records{
		Annotation: key,
		Records:    update,
	}); err != nil {
		return err
	}
	if _, err := l.file.WriteString(s.String()); err != nil {
		return err
	}
	l.file.Sync()
	return nil
}

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
		zone.zone = ns.NewZone(n, zone.Type == HintType)
		if err := zone.load(); err != nil {
			return err
		}

	case SecondaryType:
		zone.zone = ns.NewZone(n, false)
		zone.zone.Primary = zone.Primary

	case CacheType: // this is builtin and name is '.' regardless of what the configuration says
		zone.zone = cache

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

func (zone *Zone) loadKey(key, dbfile string) error {
	z := zone.zone
	db := z.Db(key)
	if db == nil {
		db = nsdb.NewText(dbfile, z.Name())
		if err := z.Attach(key, db); err != nil {
			return err
		}
	}
	t, ok := db.(*nsdb.Text)
	if !ok {
		return nil
	}
	if err := t.Load(); err != nil {
		return err
	}
	if err := z.Attach(key, t); err != nil {
		return err
	}
	logger.Printf("%v:%v: loaded from %s", z.Name(), key, dbfile)

	return nil
}

func (zone *Zone) load() error {
	z := zone.zone
	z.HoldUpdates()
	defer z.ReleaseUpdates()

	if zone.DbFile == "" {
		db := z.Db("")
		if db == nil {
			db = nsdb.NewMemory()
		}
		return z.Attach("", db)
	}

	if err := zone.loadKey("", zone.DbFile); err != nil {
		return err
	}

	for key, dbfile := range zone.InterfaceDbFiles {
		if err := zone.loadKey(key, dbfile); err != nil {
			return err
		}
	}

	updateLog, _ := z.UpdateLog.(*updateLog)
	if updateLog == nil {
		updateLog = newUpdateLog(zone.DbFile + ".log")
	}

	// replay will attach the updateLog to the zone after it replays
	if updated, err := updateLog.replay(z); err != nil {
		return err
	} else {
		if updated {
			logger.Printf("%v: updated from %s", z.Name(), updateLog.filename)
			if err := zone.save_locked(); err != nil {
				return err
			}
		}
	}

	return nil
}

func (zone *Zone) saveKey(key, dbfile string) error {
	z := zone.zone
	return z.Save(key)
}

func (zone *Zone) save() error {
	if zone.DbFile == "" {
		return nil
	}
	z := zone.zone
	z.HoldUpdates()
	defer z.ReleaseUpdates()

	return zone.save_locked()
}

func (zone *Zone) save_locked() error {
	if err := zone.saveKey("", zone.DbFile); err != nil {
		return err
	}
	for key, dbfile := range zone.InterfaceDbFiles {
		if err := zone.saveKey(key, dbfile); err != nil {
			return err
		}
	}
	z := zone.zone
	if z.UpdateLog != nil {
		z.UpdateLog.(*updateLog).reset()
	}
	return nil
}

func (zone *Zone) run(zones *ns.Zones) {
	zone.wg.Add(1)
	go func() {
		switch zone.Type {
		case PrimaryType, HintType:
			zone.primaryZone(zones)

		case SecondaryType:
			zone.secondaryZone(zones)

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
