package net

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const processAttributionTTL = 10 * time.Second

type processAttributionKey struct {
	network  string
	srcIP    string
	srcPort  uint16
	destIP   string
	destPort uint16
}

type processAttributionEntry struct {
	pid          int
	name         string
	absolutePath string
	expires      time.Time
}

var (
	processAttributionCache  sync.Map
	processAttributionSweep  atomic.Int64
	processAttributionActive atomic.Bool
)

func EnableProcessAttribution() {
	startProcessAttribution()
}

func lookupProcessAttribution(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, bool) {
	key := processAttributionKey{
		network:  network,
		srcIP:    canonicalProcessAttributionIP(srcIP),
		srcPort:  srcPort,
		destIP:   canonicalProcessAttributionIP(destIP),
		destPort: destPort,
	}
	value, found := processAttributionCache.Load(key)
	if !found {
		return 0, "", "", false
	}

	entry := value.(processAttributionEntry)
	if time.Now().After(entry.expires) {
		processAttributionCache.Delete(key)
		return 0, "", "", false
	}
	return entry.pid, entry.name, entry.absolutePath, true
}

func waitProcessAttribution(network, srcIP string, srcPort uint16, destIP string, destPort uint16) (int, string, string, bool) {
	if !processAttributionActive.Load() {
		return 0, "", "", false
	}

	deadline := time.Now().Add(50 * time.Millisecond)
	for {
		if pid, name, absolutePath, found := lookupProcessAttribution(network, srcIP, srcPort, destIP, destPort); found {
			return pid, name, absolutePath, true
		}
		if time.Now().After(deadline) {
			return 0, "", "", false
		}
		time.Sleep(time.Millisecond)
	}
}

func setProcessAttributionActive() {
	processAttributionActive.Store(true)
}

func storeProcessAttribution(network, srcIP string, srcPort uint16, destIP string, destPort uint16, pid int, name string, absolutePath string) {
	now := time.Now()
	processAttributionCache.Store(processAttributionKey{
		network:  network,
		srcIP:    canonicalProcessAttributionIP(srcIP),
		srcPort:  srcPort,
		destIP:   canonicalProcessAttributionIP(destIP),
		destPort: destPort,
	}, processAttributionEntry{
		pid:          pid,
		name:         name,
		absolutePath: absolutePath,
		expires:      now.Add(processAttributionTTL),
	})

	lastSweep := processAttributionSweep.Load()
	if now.Unix()-lastSweep < int64(processAttributionTTL.Seconds()) {
		return
	}
	if !processAttributionSweep.CompareAndSwap(lastSweep, now.Unix()) {
		return
	}
	processAttributionCache.Range(func(key, value interface{}) bool {
		entry := value.(processAttributionEntry)
		if now.After(entry.expires) {
			processAttributionCache.Delete(key)
		}
		return true
	})
}

func canonicalProcessAttributionIP(ip string) string {
	if ip == "" {
		return ""
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	return addr.Unmap().String()
}
