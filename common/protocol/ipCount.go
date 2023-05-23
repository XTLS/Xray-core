package protocol

import (
	"sync"
	"time"
)

type ExpiringMap struct {
	data map[string][]*expiringString
	mu   sync.RWMutex
}

type expiringString struct {
	value      string
	expiration int64
}

func NewExpiringMap() *ExpiringMap {
	return &ExpiringMap{
		data: make(map[string][]*expiringString),
	}
}

func (m *ExpiringMap) Get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if forItem, ok := m.data[key]; ok {
		for _, item := range forItem {
			if time.Now().UnixNano() > item.expiration {
				delete(m.data, key)
				return "", false
			}
			return item.value, true
		}
	}
	return "", false
}

func (m *ExpiringMap) Set(key string, value string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expiringValue, ok := m.data[key]
	expiration := time.Now().Add(duration).UnixNano()
	if ok {
		have := false
		for _, get := range expiringValue {
			vals := get.value
			if vals == value {
				have = true
				break
			}
		}
		if have {
			return
		}
		m.data[key] = append(expiringValue, &expiringString{value: value, expiration: int64(duration)})
	} else {
		m.data[key] = []*expiringString{{
			value:      value,
			expiration: expiration,
		}}
	}
}
