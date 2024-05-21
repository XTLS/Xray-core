package socks

import (
	"strings"
	"sync"
)

/*
In the sock implementation of * ray, UDP authentication is flawed and can be bypassed.
Tracking a UDP connection may be a bit troublesome.
Here is a simple solution.
We creat a filter, add remote IP to the pool when it try to establish a UDP connection with auth.
And drop UDP packets from unauthorized IP.
After discussion, we believe it is not necessary to add a timeout mechanism to this filter.
*/

type Filter interface {
	Check(ip string) bool
	Add(ip string) bool
	Enabled() bool
}

type UDPFilter struct {
	pool    sync.Map
	enabled bool
}

func NewUDPFilter(isEnable AuthType) Filter {
	enable := false
	if isEnable == AuthType_PASSWORD {
		enable = true
	}
	return &UDPFilter{
		pool:    sync.Map{},
		enabled: enable,
	}
}

func (f *UDPFilter) Check(ip string) bool {
	ip = stripPort(ip)
	_, exists := f.pool.Load(ip)
	return exists
}

func (f *UDPFilter) Add(ip string) bool {
	ip = stripPort(ip)
	f.pool.Store(ip, true)
	return true
}

func (f *UDPFilter) Enabled() bool {
	return f.enabled
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
