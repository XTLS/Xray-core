package stats

import (
	"sync"
	"time"
)

// OnlineMap is an implementation of stats.OnlineMap.
type OnlineMap struct {
	value         int
	ipList        map[string]time.Time
	access        sync.RWMutex
	lastCleanup   time.Time
	cleanupPeriod time.Duration
}

// NewOnlineMap creates a new instance of OnlineMap.
func NewOnlineMap() *OnlineMap {
	return &OnlineMap{
		ipList:        make(map[string]time.Time),
		lastCleanup:   time.Now(),
		cleanupPeriod: 10 * time.Second,
	}
}

// Count implements stats.OnlineMap.
func (c *OnlineMap) Count() int {
	return c.value
}

// List implements stats.OnlineMap.
func (c *OnlineMap) List() []string {
	return c.GetKeys()
}

// AddIP implements stats.OnlineMap.
func (c *OnlineMap) AddIP(ip string) {
	if ip == "127.0.0.1" {
		return
	}

	c.access.Lock()
	defer c.access.Unlock()

	if _, ok := c.ipList[ip]; !ok {
		c.ipList[ip] = time.Now()
	}
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		now := time.Now()
		for k, t := range c.ipList {
			diff := now.Sub(t)
			if diff.Seconds() > 20 {
				delete(c.ipList, k) // safe to do delete in range
			}
		}
		c.lastCleanup = time.Now()
	}

	c.value = len(c.ipList)
}

func (c *OnlineMap) GetKeys() []string {
	c.access.Lock()
	defer c.access.Unlock()

	keys := []string{}
	for k := range c.ipList {
		keys = append(keys, k)
	}
	return keys
}