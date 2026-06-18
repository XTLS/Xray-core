package utils

import (
	"runtime"
	"slices"
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

// WeakCacheList is a list that holds weak references to values.
// Use for shared expensive objects and automatic cleanup when no longer used.
// This object can be GC and no goroutine is used for cleanup.
type WeakCacheList[V any] struct {
	mu sync.Mutex
	l  []weak.Pointer[V]
}

func NewWeakCacheList[V any]() *WeakCacheList[V] {
	return new(WeakCacheList[V])
}

func (c *WeakCacheList[V]) Add(value *V) {
	if value == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	weakPtr := weak.Make(value)
	c.l = append(c.l, weakPtr)
	runtime.AddCleanup(value, func(struct{}) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.l = slices.DeleteFunc(c.l, func(p weak.Pointer[V]) bool {
			return p == weakPtr
		})
	}, struct{}{})
}

func (c *WeakCacheList[V]) Values() []*V {
	c.mu.Lock()
	defer c.mu.Unlock()

	values := make([]*V, 0, len(c.l))
	alive := make([]weak.Pointer[V], 0, len(c.l))
	for _, p := range c.l {
		v := p.Value()
		if v == nil {
			continue
		}
		alive = append(alive, p)
		values = append(values, v)
	}
	c.l = alive
	return values
}
