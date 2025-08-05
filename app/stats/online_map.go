package stats

import (
	"sync"
	"time"
)

// OnlineMap is an implementation of stats.OnlineMap.
type OnlineMap struct {
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
	c.access.RLock()
	defer c.access.RUnlock()

	return len(c.ipList)
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
	c.ipList[ip] = time.Now()
	c.access.Unlock()

	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		c.RemoveExpiredIPs()
		c.lastCleanup = time.Now()
	}
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

func (c *OnlineMap) RemoveExpiredIPs() {
	c.access.Lock()
	defer c.access.Unlock()

	now := time.Now()
	for k, t := range c.ipList {
		diff := now.Sub(t)
		if diff.Seconds() > 20 {
			delete(c.ipList, k)
		}
	}
}

func (c *OnlineMap) IpTimeMap() map[string]time.Time {
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		c.RemoveExpiredIPs()
		c.lastCleanup = time.Now()
	}

	return c.ipList
}
