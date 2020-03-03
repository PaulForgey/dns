package nsdb

import (
	"container/heap"
	"errors"
	"sync"
	"time"

	"tessier-ashpool.net/dns"
)

// MaxItems and LowItems may be changed at runtime
var MaxItems = 2000 // maximum cache entries
var LowItems = 1500 // entries purge down to

// the Cache type is a specialization of Memory which expires records
type Cache struct {
	*Memory
	lk    *sync.Mutex           // we are mutating existing records from the Memory backend
	items cacheItems            // minheap where oldest entries will pop out
	index map[string]*cacheItem // cache index
}

type cacheItem struct {
	name  dns.Name
	used  time.Time
	index int
}

type cacheItems []*cacheItem

func (c cacheItems) Len() int { return len(c) }

func (c cacheItems) Less(i, j int) bool { return c[i].used.Before(c[j].used) }

func (c cacheItems) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
	c[i].index, c[j].index = i, j
}

func (c *cacheItems) Push(item interface{}) {
	index := len(*c)
	ci := item.(*cacheItem)
	ci.index = index
	*c = append(*c, ci)
}

func (c *cacheItems) Pop() interface{} {
	oc := *c
	n := len(oc)
	ci := oc[n-1]
	oc[n-1] = nil
	ci.index = -1
	*c = oc[0 : n-1]
	return ci
}

func NewCache() *Cache {
	return &Cache{
		Memory: NewMemory(),
		lk:     &sync.Mutex{},
		index:  make(map[string]*cacheItem),
	}
}

func (c *Cache) touch_locked(now time.Time, name dns.Name) {
	key := name.Key()
	ci, ok := c.index[key]
	if !ok {
		ci = &cacheItem{
			name: name,
			used: now,
		}
		heap.Push(&c.items, ci)
		c.index[key] = ci
	} else {
		ci.used = now
		heap.Fix(&c.items, ci.index)

	}
	if c.items.Len() > MaxItems {
		for c.items.Len() > LowItems {
			ci := heap.Pop(&c.items).(*cacheItem)
			c.Memory.Enter(ci.name, nil)
			delete(c.index, ci.name.Key())
		}
	}
}

func (c *Cache) remove_locked(name dns.Name) {
	key := name.Key()
	ci, ok := c.index[key]
	if ok {
		heap.Remove(&c.items, ci.index)
		delete(c.index, key)
	}
}

func (c *Cache) Lookup(name dns.Name) (*RRMap, error) {
	return c.lookup(time.Now(), name)
}

func (c *Cache) lookup(now time.Time, name dns.Name) (*RRMap, error) {
	c.lk.Lock()
	defer c.lk.Unlock()

	value, err := c.Memory.Lookup(name)
	if errors.Is(err, dns.NXDomain) && value != nil {
		if now.Before(value.Negative) {
			err = ErrNegativeAnswer
		} else {
			c.Memory.Enter(name, nil)
		}
	}
	if err != nil {
		return nil, err
	}
	if value.Expire(now) {
		return nil, dns.NXDomain
	}
	if !value.Sticky {
		c.touch_locked(now, name)
	}
	return value, nil
}

func (c *Cache) Enter(name dns.Name, value *RRMap) error {
	return c.enter(time.Now(), name, value)
}

func (c *Cache) enter(now time.Time, name dns.Name, value *RRMap) error {
	c.lk.Lock()
	if value != nil {
		if !value.Sticky {
			c.touch_locked(now, name)
		}
	} else {
		c.remove_locked(name)
	}
	c.lk.Unlock()

	return c.Memory.Enter(name, value)
}
