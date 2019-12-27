package resolver

import (
	"testing"

	"tessier-ashpool.net/dns"
)

func TestRoot(t *testing.T) {
	root := NewRootZone()
	a, _ := root.Lookup("", newName(t, "a.root-servers.net"), dns.AnyType, dns.INClass)
	if len(a) == 0 {
		t.Fatal("no root cache entry")
	}
	for _, r := range a {
		t.Log(r)
	}
}
