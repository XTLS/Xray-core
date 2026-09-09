package utils

import (
	"maps"
	"runtime"
	"sync"
	"weak"
)

// WeakCacheMap is a map that holds weak references to values.
// Use for shared expensive objects and automatic cleanup when no longer used.
// This object can be GC and no goroutine is used for cleanup.
type WeakCacheMap[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]weak.Pointer[V]
}

func NewWeakCacheMap[K comparable, V any]() *WeakCacheMap[K, V] {
	return &WeakCacheMap[K, V]{
		m: make(map[K]weak.Pointer[V]),
	}
}

func (c *WeakCacheMap[K, V]) Load(key K) (value *V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	weakPtr := c.m[key].Value()
	if weakPtr != nil {
		return weakPtr, true
	}
	return nil, false
}

func (c *WeakCacheMap[K, V]) Store(key K, value *V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	weakPtr := weak.Make(value)
	c.m[key] = weakPtr
	runtime.AddCleanup(value, func(struct{}) {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.m[key] == weakPtr {
			delete(c.m, key)
		}
	}, struct{}{})
}

func (c *WeakCacheMap[K, V]) Range(f func(K, *V) bool) {
	c.mu.Lock()
	snapshot := maps.Clone(c.m)
	c.mu.Unlock()
	for k, v := range snapshot {
		if value := v.Value(); value != nil {
			if !f(k, value) {
				break
			}
		}
	}
}
