package test

import (
	"errors"
	"io"
	"strings"

	"tessier-ashpool.net/dns"
)

// NewRecord creates a record from a valid string with no default domain. panics if an error occurs
func NewRecord(s string) *dns.Record {
	c := dns.NewTextReader(strings.NewReader(s), nil)
	r := &dns.Record{}
	if err := c.Decode(r); err != nil {
		panic(err)
	}
	return r
}

// NewRecordSet creates an array of records from a multiline string. panics if an error occurs
func NewRecordSet(origin dns.Name, s string) []*dns.Record {
	var result []*dns.Record

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
		result = append(result, r)
	}
	return result
}

// NewRecords creates a Records from a valid string. panics if an error occurs
func NewRecords(s string) *dns.Records {
	c := dns.NewTextReader(strings.NewReader(s), nil)
	records := &dns.Records{}
	if err := c.Decode(records); err != nil {
		panic(err)
	}
	return records
}
