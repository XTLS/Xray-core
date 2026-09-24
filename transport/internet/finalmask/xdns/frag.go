package xdns

import (
	"sync"
	"time"
)

const (
	fragTTL          = 8 * time.Second
	fragSize         = 4096
	fragClientIDSize = 16384
	fragCount        = 4096
)

type FragKey struct {
	clientID ClientID
	fragID   byte
}

type FragEntry struct {
	data     [][]byte
	size     int
	len      int
	total    byte
	deadline time.Time
}

type FragManager struct {
	m     map[FragKey]*FragEntry
	sizem map[ClientID]int
	ch    chan struct{}
	mu    sync.Mutex
}

func NewFragManager() *FragManager {
	m := &FragManager{
		m:     make(map[FragKey]*FragEntry),
		sizem: make(map[ClientID]int),
		ch:    make(chan struct{}),
	}
	go m.gc()
	return m
}

func (m *FragManager) closed() bool {
	select {
	case <-m.ch:
		return true
	default:
		return false
	}
}

func (m *FragManager) removeEntey(k FragKey, e *FragEntry) {
	m.sizem[k.clientID] -= e.size
	delete(m.m, k)
}

func (m *FragManager) tryRemove() {
	if len(m.m) < fragCount {
		return
	}
	var key FragKey
	var entry *FragEntry
	first := true
	for k, e := range m.m {
		if first || e.deadline.Before(entry.deadline) {
			key = k
			entry = e
			first = false
		}
	}
	m.removeEntey(key, entry)
}

func (m *FragManager) gc() {
	ticker := time.NewTicker(fragTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-m.ch:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			for k, e := range m.m {
				if now.After(e.deadline) {
					m.removeEntey(k, e)
				}
			}
			m.mu.Unlock()
		}
	}
}

func (m *FragManager) Feed(out []byte, key FragKey, fragIdx, fragN byte, data []byte) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return 0
	}

	if fragN < 2 {
		return 0
	}

	now := time.Now()
	entry := m.m[key]
	if entry == nil || now.After(entry.deadline) {
		if entry == nil {
			m.tryRemove()
		} else {
			m.removeEntey(key, entry)
		}
		entry = &FragEntry{
			data:     make([][]byte, fragN),
			total:    fragN,
			deadline: now.Add(fragTTL),
		}
		m.m[key] = entry
	}

	if fragN != entry.total {
		return 0
	}
	if fragIdx >= entry.total {
		return 0
	}
	if entry.data[fragIdx] != nil {
		return 0
	}
	if entry.size+len(data) > fragSize {
		return 0
	}
	if entry.len < int(entry.total)-1 {
		if m.sizem[key.clientID]+len(data) > fragClientIDSize {
			return 0
		}
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	entry.data[fragIdx] = cp
	entry.size += len(data)
	entry.len++
	entry.deadline = now.Add(fragTTL)
	m.sizem[key.clientID] += len(data)

	if entry.len < int(entry.total) {
		return 0
	}

	out = out[:0]
	for i := range entry.data {
		out = append(out, entry.data[i]...)
	}
	m.removeEntey(key, entry)
	return len(out)
}

func (m *FragManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	close(m.ch)
	for k := range m.m {
		delete(m.m, k)
	}
}
