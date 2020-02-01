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

func (c *Cache) Lookup(name dns.Name) (RRMap, error) {
	now := time.Now()

	c.lk.Lock()
	defer c.lk.Unlock()

	value, err := c.Memory.Lookup(name)
	if err != nil {
		return nil, err
	}
	value.Expire(now)
	if len(value) == 0 {
		return nil, dns.NXDomain
	}

	return value, nil
}
