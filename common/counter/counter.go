package counter

import "sync/atomic"

type Counter[i int32 | int64] interface {
	Get() i
	Set(i) (old i)
	Add(i) (new i)
}

type counter32 struct {
	value int32
}

func NewCounter32(initialValue int32) Counter[int32] {
	return &counter32{value: initialValue}
}

func (c *counter32) Get() int32 {
	return atomic.LoadInt32(&c.value)
}

func (c *counter32) Set(newValue int32) int32 {
	return atomic.SwapInt32(&c.value, newValue)
}

func (c *counter32) Add(delta int32) int32 {
	return atomic.AddInt32(&c.value, delta)
}

type counter64 struct {
	value int64
}

func NewCounter64(initialValue int64) Counter[int64] {
	return &counter64{value: initialValue}
}

func (c *counter64) Get() int64 {
	return atomic.LoadInt64(&c.value)
}

func (c *counter64) Set(newValue int64) int64 {
	return atomic.SwapInt64(&c.value, newValue)
}

func (c *counter64) Add(delta int64) int64 {
	return atomic.AddInt64(&c.value, delta)
}
