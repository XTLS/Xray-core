package utils

import (
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

func probeRoutes() (ipv4 bool, ipv6 bool) {
	if conn, err := net.Dial("udp4", "192.33.4.12:53"); err == nil {
		ipv4 = true
		conn.Close()
	}
	if conn, err := net.Dial("udp6", "[2001:500:2::c]:53"); err == nil {
		ipv6 = true
		conn.Close()
	}
	return
}

var routeCache struct {
	sync.Once
	sync.RWMutex
	expire     time.Time
	ipv4, ipv6 bool
}

func CheckRoutes() (bool, bool) {
	if !isGUIPlatform {
		routeCache.Once.Do(func() {
			routeCache.ipv4, routeCache.ipv6 = probeRoutes()
		})
		return routeCache.ipv4, routeCache.ipv6
	}

	routeCache.RWMutex.RLock()
	now := time.Now()
	if routeCache.expire.After(now) {
		routeCache.RWMutex.RUnlock()
		return routeCache.ipv4, routeCache.ipv6
	}
	routeCache.RWMutex.RUnlock()

	routeCache.RWMutex.Lock()
	defer routeCache.RWMutex.Unlock()

	now = time.Now()
	if routeCache.expire.After(now) { // double-check
		return routeCache.ipv4, routeCache.ipv6
	}
	routeCache.ipv4, routeCache.ipv6 = probeRoutes()    // ~2ms
	routeCache.expire = now.Add(100 * time.Millisecond) // ttl
	return routeCache.ipv4, routeCache.ipv6
}

var isGUIPlatform = detectGUIPlatform()

func detectGUIPlatform() bool {
	switch runtime.GOOS {
	case "android", "ios", "windows", "darwin":
		return true
	case "linux", "freebsd", "openbsd":
		if t := os.Getenv("XDG_SESSION_TYPE"); t == "wayland" || t == "x11" {
			return true
		}
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			return true
		}
	}
	return false
}
