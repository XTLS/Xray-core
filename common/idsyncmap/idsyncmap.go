package idsyncmap

import (
	"sync"

	"github.com/4nd3r5on/Xray-core/common/counter"
)

type IDSyncMap[T any] interface {
	Add(T) int32
	Remove(id int32)
	Get() map[int32]T
}

type idSyncMap[T any] struct {
	data   map[int32]T
	mu     *sync.RWMutex
	nextID counter.Counter[int32]
}

func NewIDSyncMap[T any]() IDSyncMap[T] {
	return &idSyncMap[T]{
		data:   make(map[int32]T),
		mu:     &sync.RWMutex{},
		nextID: counter.NewCounter32(0),
	}
}

func (c *idSyncMap[T]) Add(callback T) int32 {
	id := c.nextID.Get()
	c.mu.Lock()
	c.data[id] = callback
	c.mu.Unlock()
	c.nextID.Add(1)
	return id
}

func (c *idSyncMap[T]) Remove(id int32) {
	delete(c.data, id)
}

func (c *idSyncMap[T]) Get() map[int32]T {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data
}
