package test

import (
	"errors"
	"io"
	"strings"
	"time"

	"tessier-ashpool.net/dns"
	"tessier-ashpool.net/dns/nsdb"
)

// LoadDb loads a database with zone file contents. panics if an error occurs
func LoadDb(db nsdb.Db, origin dns.Name, s string) {
	if err := db.Clear(); err != nil {
		panic(err)
	}
	records := make([]*dns.Record, 0, 64)

	c := dns.NewTextReader(strings.NewReader(s), origin)
	for {
		r := &dns.Record{}
		err := c.Decode(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			panic(err)
		}
		if len(records) == cap(records) {
			_, err := nsdb.Load(db, time.Time{}, records)
			if err != nil {
				panic(err)
			}
			records = records[:0]
		}
		records = append(records, r)
	}
	if len(records) > 0 {
		_, err := nsdb.Load(db, time.Time{}, records)
		if err != nil {
			panic(err)
		}
	}
}
