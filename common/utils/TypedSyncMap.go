package util

import (
	"sync"
)

// TypedSyncMap is a wrapper of sync.Map that provides type-safe for keys and values.
// No need to use type assertions every time, so you can have more time to enjoy other things like GochiUsa
type TypedSyncMap[K, V any] struct {
	syncMap *sync.Map
}

func NewTypedSyncMap[K any, V any]() *TypedSyncMap[K, V] {
	return &TypedSyncMap[K, V]{
		syncMap: &sync.Map{},
	}
}

func (m *TypedSyncMap[K, V]) Clear() {
	m.syncMap.Clear()
}

func (m *TypedSyncMap[K, V]) CompareAndDelete(key K, old V) (deleted bool) {
	return m.syncMap.CompareAndDelete(key, old)
}

func (m *TypedSyncMap[K, V]) CompareAndSwap(key K, old V, new V) (swapped bool) {
	return m.syncMap.CompareAndSwap(key, old, new)
}

func (m *TypedSyncMap[K, V]) Delete(key K) {
	m.syncMap.Delete(key)
}

func (m *TypedSyncMap[K, V]) Load(key K) (value V, ok bool) {
	anyValue, ok := m.syncMap.Load(key)
	return anyValue.(V), ok
}

func (m *TypedSyncMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	anyValue, loaded := m.syncMap.LoadAndDelete(key)
	return anyValue.(V), loaded
}
func (m *TypedSyncMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	anyActual, loaded := m.syncMap.LoadOrStore(key, value)
	return anyActual.(V), loaded
}
func (m *TypedSyncMap[K, V]) Range(f func(key K, value V) bool) {
	m.syncMap.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
func (m *TypedSyncMap[K, V]) Store(key K, value V) {
	m.syncMap.Store(key, value)
}
func (m *TypedSyncMap[K, V]) Swap(key K, value V) (previous V, loaded bool) {
	anyPrevious, loaded := m.syncMap.Swap(key, value)
	return anyPrevious.(V), loaded
}