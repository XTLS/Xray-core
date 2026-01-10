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
	ipTimeout     time.Duration
	maxIPs        int
}

// NewOnlineMap creates a new instance of OnlineMap.
func NewOnlineMap() *OnlineMap {
	return &OnlineMap{
		ipList:        make(map[string]time.Time),
		lastCleanup:   time.Now(),
		cleanupPeriod: 10 * time.Second,
		ipTimeout:     20 * time.Second,
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
	defer c.access.Unlock()
	c.ipList[ip] = time.Now()
	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		c.removeExpiredIPsLocked()
	}
}

// TryAddIP atomically checks if an IP can be added and adds it if allowed.
func (c *OnlineMap) TryAddIP(ip string) bool {
	if ip == "127.0.0.1" {
		return true
	}

	c.access.Lock()
	defer c.access.Unlock()

	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		c.removeExpiredIPsLocked()
	}
	if _, exists := c.ipList[ip]; exists {
		c.ipList[ip] = time.Now()
		return true
	}

	if c.maxIPs > 0 && len(c.ipList) >= c.maxIPs {
		return false
	}
	c.ipList[ip] = time.Now()
	return true
}

// SetMaxIPs sets the maximum concurrent IPs allowed.
func (c *OnlineMap) SetMaxIPs(max int) {
	c.access.Lock()
	defer c.access.Unlock()
	c.maxIPs = max
}

func (c *OnlineMap) GetKeys() []string {
	c.access.RLock()
	defer c.access.RUnlock()

	keys := make([]string, 0, len(c.ipList))
	for k := range c.ipList {
		keys = append(keys, k)
	}
	return keys
}

// RemoveExpiredIPs allows manual cleanup of expired IPs.
func (c *OnlineMap) RemoveExpiredIPs() {
	c.access.Lock()
	defer c.access.Unlock()
	c.removeExpiredIPsLocked()
}

// removeExpiredIPsLocked removes expired IPs. Caller must hold the lock.
func (c *OnlineMap) removeExpiredIPsLocked() {
	now := time.Now()
	for k, t := range c.ipList {
		if now.Sub(t) > c.ipTimeout {
			delete(c.ipList, k)
		}
	}
	c.lastCleanup = now
}

func (c *OnlineMap) IpTimeMap() map[string]time.Time {
	c.access.Lock()
	defer c.access.Unlock()

	if time.Since(c.lastCleanup) > c.cleanupPeriod {
		c.removeExpiredIPsLocked()
	}

	result := make(map[string]time.Time, len(c.ipList))
	for k, v := range c.ipList {
		result[k] = v
	}
	return result
}
