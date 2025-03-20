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
	list := c.ipList

	if ip == "127.0.0.1" {
		return
	}
	c.access.Lock()
	if _, ok := list[ip]; !ok {
		list[ip] = time.Now()
	}
	c.access.Unlock()
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		list = c.RemoveExpiredIPs(list)
		c.lastCleanup = time.Now()
	}

	c.value = len(list)
	c.ipList = list
}

func (c *OnlineMap) GetKeys() []string {
	c.access.RLock()
	defer c.access.RUnlock()

	keys := []string{}
	for k := range c.ipList {
		keys = append(keys, k)
	}
	return keys
}

func (c *OnlineMap) RemoveExpiredIPs(list map[string]time.Time) map[string]time.Time {
	c.access.Lock()
	defer c.access.Unlock()

	now := time.Now()
	for k, t := range list {
		diff := now.Sub(t)
		if diff.Seconds() > 20 {
			delete(list, k)
		}
	}
	return list
}

func (c *OnlineMap) IpTimeMap() map[string]time.Time {
	list := c.ipList
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		list = c.RemoveExpiredIPs(list)
		c.lastCleanup = time.Now()
	}

	return c.ipList
}
