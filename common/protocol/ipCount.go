package protocol

import (
	"strings"
	"sync"
	"time"
)

type ExpiringMap struct {
	data map[string]*expiringString
	mu   sync.RWMutex
}

type expiringString struct {
	value      string
	expiration int64
}

func NewExpiringMap() *ExpiringMap {
	return &ExpiringMap{
		data: make(map[string]*expiringString),
	}
}

func (m *ExpiringMap) Get(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if item, ok := m.data[key]; ok {
		if time.Now().UnixNano() > item.expiration {
			delete(m.data, key)
			return "", false
		}
		return item.value, true
	}
	return "", false
}

func (m *ExpiringMap) Set(key string, value string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	expiringValue, ok := m.data[key]
	expiration := time.Now().Add(duration).UnixNano()
	if ok {
		vals := strings.Split(expiringValue.value, ",")
		have := false
		for _, v := range vals {
			if v == value {
				have = true
				break
			}
		}
		if !have {
			expiringValue.value += "," + value
		} else {
			expiringValue.value = expiringValue.value
		}
		expiringValue.expiration = expiration
		m.data[key] = expiringValue

	} else {
		m.data[key] = &expiringString{
			value:      value,
			expiration: expiration,
		}
	}
}
