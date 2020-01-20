package nsdb

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"tessier-ashpool.net/dns"
)

// the Text type is an in memory implementation of Db backed by a textual zone file
type Text struct {
	*Memory
	pathname string
}

// NewText creates an instance of Text but does not load contents. Call Load to do that.
func NewText(pathname string) *Text {
	return &Text{
		Memory:   NewMemory(),
		pathname: pathname,
	}
}

func (t *Text) Flags() DbFlags {
	return 0
}

// Load parses the zone file
func (t *Text) Load(name dns.Name) error {
	if err := t.BeginUpdate(); err != nil {
		return err
	}
	abort := true
	defer func() {
		t.EndUpdate(abort)
	}()

	c, err := dns.NewTextFileReader(t.pathname, name)
	if err != nil {
		return err
	}

	if err := t.Clear(); err != nil {
		return err
	}

	records := make([]*dns.Record, 0, 256)
	for {
		r := &dns.Record{}
		if err := c.Decode(r); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		records = append(records, r)

		if len(records) == cap(records) {
			if _, err := Load(t, time.Time{}, records); err != nil {
				return err
			}
			records = records[:0]
		}
	}
	if len(records) > 0 {
		if _, err := Load(t, time.Time{}, records); err != nil {
			return err
		}
	}

	abort = false
	return nil
}

func (t *Text) Save(name dns.Name) error {
	tmpfile := fmt.Sprintf("%s-%d", t.pathname, os.Getpid())
	out, err := os.Create(tmpfile)
	if err != nil {
		return err
	}

	bw := bufio.NewWriter(out)
	w := dns.NewTextWriter(bw)

	soa, _ := t.Lookup(true, name, dns.SOAType, dns.AnyClass)
	if soa != nil {
		for _, r := range soa.Records {
			if err := w.Encode(r); err != nil {
				return err
			}
		}
	}
	if err := t.Enumerate(0, func(serial uint32, records []*dns.Record) error {
		for _, r := range records {
			if r.Type() == dns.SOAType && name.Equal(r.Name()) {
				continue
			}
			if err := w.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if err := bw.Flush(); err != nil {
		return err
	}

	if err := out.Sync(); err != nil {
		return err
	}
	out.Close()

	return os.Rename(tmpfile, t.pathname)
}
