package resolver

import (
	"testing"

	"tessier-ashpool.net/dns"
)

func nameWithString(t *testing.T, s string) dns.Name {
	name, err := dns.NameWithString(s)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestRoot(t *testing.T) {
	root := RootCache.Find(nil)
	a, _, err := root.Lookup("", nameWithString(t, "a.root-servers.net"), dns.AnyType, dns.INClass)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) == 0 {
		t.Fatal("no root cache entry")
	}
	for _, r := range a {
		t.Log(r)
	}
}
