package socks

import (
	"strings"
	"sync"
	"time"
)

/*
In the sock implementation of * ray, UDP authentication is flawed and can be bypassed.
Tracking a UDP connection may be a bit troublesome.
Here is a simple solution.
We creat a filter, add remote IP to the pool when it try to establish a UDP connection with auth.
And drop UDP packets from unauthorized IP.
*/

type Filter interface {
	Check(ip string) bool
	Add(ip string) bool
}

type UDPFilter struct {
	access    sync.Mutex
	lastClean time.Time
	timeout   time.Duration
	pool      map[string]time.Time
}

func NewUDPFilter(timeout time.Duration) Filter {
	return &UDPFilter{
		lastClean: time.Now(),
		pool:      make(map[string]time.Time),
		timeout:   timeout,
	}
}

func (f *UDPFilter) Check(ip string) bool {
	ip = stripPort(ip)
	now := time.Now()
	f.access.Lock()
	defer f.access.Unlock()

	if now.Sub(f.lastClean) > f.timeout {
		for oldIP, added := range f.pool {
			if now.Sub(added) > f.timeout {
				delete(f.pool, oldIP)
			}
		}
		f.lastClean = now
	}

	if added, loaded := f.pool[ip]; loaded && now.Sub(added) <= f.timeout {
		return true
	}

	return false
}

func (f *UDPFilter) Add(ip string) bool {
	ip = stripPort(ip)
	now := time.Now()
	f.access.Lock()
	defer f.access.Unlock()
	f.pool[ip] = now
	return true
}

// conn.RemoteAddr().String() will return an address with a port like 11.45.1.4:1919
// We just need 11.45.1.4
func stripPort(ip string) string {
	if strings.HasPrefix(ip, "[") {
		end := strings.Index(ip, "]")
		if end != -1 && end < len(ip)-1 && ip[end+1] == ':' {
			return ip[:end+1]
		}
	} else {
		if colon := strings.LastIndex(ip, ":"); colon != -1 {
			return ip[:colon]
		}
	}
	return ip
}
