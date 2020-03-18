package test

import (
	"tessier-ashpool.net/dns"
)

// NewName creates a dns.Name from a valid string. panics if an error occurs.
func NewName(s string) dns.Name {
	n, err := dns.NameWithString(s)
	if err != nil {
		panic(err)
	}
	return n
}
