package utils

import (
	"sync/atomic"
	"time"
)

type AtomicTime struct {
	v atomic.Value
}

func NewAtomicTime(t time.Time) *AtomicTime {
	a := &AtomicTime{}
	a.Set(t)
	return a
}

func (t *AtomicTime) Set(new time.Time) {
	t.v.Store(new)
}

func (t *AtomicTime) Get() time.Time {
	return t.v.Load().(time.Time)
}

type Atomic[T any] struct {
	v atomic.Value
}

func (a *Atomic[T]) Load() T {
	value := a.v.Load()
	if value == nil {
		var zero T
		return zero
	}
	return value.(T)
}

func (a *Atomic[T]) Store(value T) {
	a.v.Store(value)
}

func (a *Atomic[T]) Swap(new T) T {
	old := a.v.Swap(new)
	if old == nil {
		var zero T
		return zero
	}
	return old.(T)
}

func (a *Atomic[T]) CompareAndSwap(old, new T) bool {
	return a.v.CompareAndSwap(old, new)
}
