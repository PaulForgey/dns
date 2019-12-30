package resolver

import (
	"testing"

	"tessier-ashpool.net/dns"
)

func TestRoot(t *testing.T) {
	root := NewRootZone()
	a, _, err := root.Lookup("", newName(t, "a.root-servers.net"), dns.AnyType, dns.INClass)
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
