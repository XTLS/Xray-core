package xpool

import (
	"sync"

	"github.com/xtls/xray-core/common/buf"
)

type SendEntry struct {
	Seq    uint32
	Buffer *buf.Buffer
}

type SendBuffer struct {
	entries  []*SendEntry
	capacity int
	head     int
	tail     int
	count    int
	mu       sync.Mutex
}

func NewSendBuffer(capacity int) *SendBuffer {
	return &SendBuffer{
		entries:  make([]*SendEntry, capacity),
		capacity: capacity,
	}
}

func (b *SendBuffer) Add(seq uint32, buffer *buf.Buffer) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.count >= b.capacity {
		return false
	}

	b.entries[b.tail] = &SendEntry{
		Seq:    seq,
		Buffer: buffer,
	}
	b.tail = (b.tail + 1) % b.capacity
	b.count++
	return true
}

func (b *SendBuffer) OnAck(ack uint32) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	released := 0
	for b.count > 0 {
		entry := b.entries[b.head]
		if entry.Seq >= ack {
			break
		}

		entry.Buffer.Release()
		b.entries[b.head] = nil
		b.head = (b.head + 1) % b.capacity
		b.count--
		released++
	}
	return released
}

func (b *SendBuffer) GetUnacked() []*SendEntry {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]*SendEntry, 0, b.count)
	idx := b.head
	for i := 0; i < b.count; i++ {
		result = append(result, b.entries[idx])
		idx = (idx + 1) % b.capacity
	}
	return result
}

func (b *SendBuffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	idx := b.head
	for i := 0; i < b.count; i++ {
		if b.entries[idx] != nil {
			b.entries[idx].Buffer.Release()
			b.entries[idx] = nil
		}
		idx = (idx + 1) % b.capacity
	}
	b.head = 0
	b.tail = 0
	b.count = 0
}
