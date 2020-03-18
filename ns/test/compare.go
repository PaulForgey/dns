package test

import (
	"tessier-ashpool.net/dns"
)

// SameRecordSet returns true if rs1 and rs2 contain all the same records
func SameRecordSet(rs1, rs2 []*dns.Record) bool {
	return len(dns.Subtract(rs1, rs2)) == 0 && len(dns.Subtract(rs2, rs1)) == 0
}

// IncludedRecordSet returns true if all records in included are contained by rs
func IncludedRecordSet(rs, included []*dns.Record) bool {
	return len(dns.Subtract(included, rs)) == 0
}

// ExludedRecordSet returns true if all records in excluded are not contained by rs
func ExcludedRecordSet(rs, excluded []*dns.Record) bool {
	return len(rs) == len(dns.Subtract(rs, excluded))
}
