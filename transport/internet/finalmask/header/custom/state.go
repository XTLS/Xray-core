package custom

import (
	"sync"
	"time"
)

type stateEntry struct {
	vars      map[string][]byte
	expiresAt time.Time
}

type stateStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]stateEntry
}

func newStateStore(ttl time.Duration) *stateStore {
	return &stateStore{
		ttl:     ttl,
		entries: make(map[string]stateEntry),
	}
}

func (s *stateStore) get(key string) (map[string][]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return nil, false
	}
	return cloneVars(entry.vars), true
}

func (s *stateStore) set(key string, vars map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[key] = stateEntry{
		vars:      cloneVars(vars),
		expiresAt: time.Now().Add(s.ttl),
	}
}

func cloneVars(vars map[string][]byte) map[string][]byte {
	cloned := make(map[string][]byte, len(vars))
	for key, value := range vars {
		cloned[key] = append([]byte(nil), value...)
	}
	return cloned
}
