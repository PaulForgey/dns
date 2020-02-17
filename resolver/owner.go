package resolver

import (
	"fmt"

	"tessier-ashpool.net/dns"
)

// the OwnerNames type contains OwnerName entries indexed by dns.Name
type OwnerNames map[string]*OwnerName

type OwnerName struct {
	Name      dns.Name      // name of RRSets
	Z         ZoneAuthority // zone authority for the name
	RRSets    IfaceRRSets   // RRSets for the name
	Exclusive bool          // has CacheFlush records
}

// the IfaceRRSet type contains a list of interface specific RRSets for each interface, indexed by interface name.
// records in common with all interfaces are keyed by the empty string.
type IfaceRRSets map[string][]*dns.Record

// EnterOwnerNames breaks out a mixed set of IfaceRRSet records into a list of OwnerName elements of like names
func (n OwnerNames) Enter(auth Authority, iface string, records []*dns.Record) error {
	err := dns.RecordSets(records, func(name dns.Name, records []*dns.Record) error {
		owner, ok := n[name.Key()]
		if !ok {
			var z ZoneAuthority
			if auth != nil {
				z = auth.Find(name)
				if z == nil {
					// add only the records we know about and do not fail the operation
					return nil
				}
			}
			owner = &OwnerName{
				Name:      name,
				Z:         z,
				RRSets:    make(IfaceRRSets),
				Exclusive: dns.CacheFlush(records[0].H),
			}
			n[name.Key()] = owner
		}
		for _, r := range records {
			if dns.CacheFlush(r.H) != owner.Exclusive {
				return fmt.Errorf("%w: mix of exclusive and shared records in %v",
					dns.FormError, name)
			}
		}

		owner.RRSets.Add(iface, records)
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

// Questions returns a list of appropriate probing questions and authority records for the set of names
func (n OwnerNames) Questions() ([]dns.Question, IfaceRRSets) {
	var questions []dns.Question
	authority := make(IfaceRRSets)

	for _, owner := range n {
		if !owner.Exclusive {
			continue
		}
		for iface, irecords := range owner.RRSets {
			dns.RecordSets(irecords, func(name dns.Name, records []*dns.Record) error {
				for _, r := range records {
					found := false
					for _, q := range questions {
						if q.Name().Equal(name) && q.Class() == r.Class() {
							found = true
							break
						}
					}
					if !found {
						questions = append(
							questions,
							dns.NewMDNSQuestion(name, dns.AnyType, r.Class(), true),
						)
					}
				}
				authority.Add(iface, records)
				return nil
			})
		}
	}

	return questions, authority
}

// Records returns a compound list of records for the interface merged with the non-interface specific
func (s IfaceRRSets) Records(iface string) []*dns.Record {
	irecords, _ := s[iface]
	if iface == "" {
		return irecords
	}
	records, _ := s[""]
	return dns.Merge(records, irecords)
}

// Enter adds interface specific records to the set.
// An error is returned if shared records are added to existing exclusive ones or vice versa.
func (s IfaceRRSets) Add(iface string, records []*dns.Record) {
	irecords, _ := s[iface]
	s[iface] = dns.Merge(irecords, records)
}
