package nsdb

import (
	"sync"
	"time"

	"tessier-ashpool.net/dns"
)

// the Cache type is a specialization of Memory which expires records
type Cache struct {
	*Memory
	lk *sync.Mutex // we are mutating existing records from the Memory backend
}

func NewCache() *Cache {
	return &Cache{
		Memory: NewMemory(),
		lk:     &sync.Mutex{},
	}
}

func (c *Cache) Lookup(exact bool, name dns.Name, rrtype dns.RRType, rrclass dns.RRClass) (*RRSet, error) {
	now := time.Now()

	c.lk.Lock()
	defer c.lk.Unlock()

	rr, err := c.Memory.Lookup(exact, name, rrtype, rrclass)
	if err != nil {
		return nil, err
	}

	if rr != nil && rr.Expire(now) {
		rr = nil
		c.Memory.Enter(name, rrtype, rrclass, nil)
	}

	return rr, nil
}
