// Advanced Memory Pool for Zero-Copy Buffer Management
package sush

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// BufferPool manages reusable byte buffers for high-performance I/O
type BufferPool struct {
	pools   []sync.Pool
	sizes   []int
	stats   BufferPoolStats
	maxSize int
}

// BufferPoolStats tracks buffer pool performance
type BufferPoolStats struct {
	mu             sync.RWMutex
	BuffersReused  int64
	BuffersCreated int64
	BytesReused    int64
	BytesAllocated int64
	PoolHitRate    float64
}

// ManagedBuffer represents a buffer that returns to pool when released
type ManagedBuffer struct {
	data []byte
	pool *BufferPool
	size int
}

// NewBufferPool creates a new buffer pool with predefined sizes
func NewBufferPool() *BufferPool {
	// Common buffer sizes for network I/O
	sizes := []int{
		64,    // Small packets
		256,   // Medium packets
		1024,  // Standard MTU
		4096,  // Page size
		8192,  // Large packets
		16384, // Very large packets
		65536, // Maximum reasonable size
	}

	pools := make([]sync.Pool, len(sizes))
	for i, size := range sizes {
		size := size // Capture for closure
		pools[i] = sync.Pool{
			New: func() interface{} {
				buffer := make([]byte, size)
				return buffer
			},
		}
	}

	return &BufferPool{
		pools:   pools,
		sizes:   sizes,
		maxSize: sizes[len(sizes)-1],
	}
}

// Get acquires a buffer of at least the specified size
func (bp *BufferPool) Get(size int) *ManagedBuffer {
	if size <= 0 {
		size = 1024 // Default size
	}

	if size > bp.maxSize {
		// Size too large for pool, allocate directly
		atomic.AddInt64(&bp.stats.BuffersCreated, 1)
		atomic.AddInt64(&bp.stats.BytesAllocated, int64(size))
		return &ManagedBuffer{
			data: make([]byte, size),
			pool: bp,
			size: -1, // Indicates direct allocation
		}
	}

	// Find the appropriate pool
	poolIndex := bp.findPoolIndex(size)
	if poolIndex == -1 {
		// Fallback to direct allocation
		atomic.AddInt64(&bp.stats.BuffersCreated, 1)
		atomic.AddInt64(&bp.stats.BytesAllocated, int64(size))
		return &ManagedBuffer{
			data: make([]byte, size),
			pool: bp,
			size: -1,
		}
	}

	// Get from pool
	buffer := bp.pools[poolIndex].Get().([]byte)
	atomic.AddInt64(&bp.stats.BuffersReused, 1)
	atomic.AddInt64(&bp.stats.BytesReused, int64(len(buffer)))

	return &ManagedBuffer{
		data: buffer[:size], // Slice to requested size
		pool: bp,
		size: poolIndex,
	}
}

// findPoolIndex finds the smallest pool that can accommodate the size
func (bp *BufferPool) findPoolIndex(size int) int {
	for i, poolSize := range bp.sizes {
		if size <= poolSize {
			return i
		}
	}
	return -1
}

// GetStats returns current buffer pool statistics
func (bp *BufferPool) GetStats() BufferPoolStats {
	bp.stats.mu.RLock()
	defer bp.stats.mu.RUnlock()

	stats := bp.stats

	// Calculate hit rate
	total := stats.BuffersReused + stats.BuffersCreated
	if total > 0 {
		stats.PoolHitRate = float64(stats.BuffersReused) / float64(total) * 100.0
	}

	return stats
}

// ManagedBuffer methods

// Data returns the underlying byte slice
func (mb *ManagedBuffer) Data() []byte {
	return mb.data
}

// Len returns the length of the buffer
func (mb *ManagedBuffer) Len() int {
	return len(mb.data)
}

// Cap returns the capacity of the buffer
func (mb *ManagedBuffer) Cap() int {
	return cap(mb.data)
}

// Release returns the buffer to the pool for reuse
func (mb *ManagedBuffer) Release() {
	if mb.pool == nil || mb.size == -1 {
		// Direct allocation, just let GC handle it
		mb.data = nil
		return
	}

	// Clear sensitive data (security best practice)
	for i := range mb.data {
		mb.data[i] = 0
	}

	// Restore original size and return to pool
	originalSize := mb.pool.sizes[mb.size]
	mb.data = mb.data[:originalSize]
	mb.pool.pools[mb.size].Put(mb.data)

	// Clear references
	mb.data = nil
	mb.pool = nil
}

// Resize creates a new buffer with different size, releasing the old one
func (mb *ManagedBuffer) Resize(newSize int) *ManagedBuffer {
	if newSize <= 0 {
		mb.Release()
		return nil
	}

	newBuffer := mb.pool.Get(newSize)

	// Copy existing data if any
	if len(mb.data) > 0 && newSize > 0 {
		copySize := len(mb.data)
		if copySize > newSize {
			copySize = newSize
		}
		copy(newBuffer.data[:copySize], mb.data[:copySize])
	}

	mb.Release()
	return newBuffer
}

// Zero-Copy Buffer Ring for High-Throughput Scenarios
type RingBuffer struct {
	buffer   []byte
	readPos  int64
	writePos int64
	size     int64
	mask     int64
	mu       sync.RWMutex
}

// NewRingBuffer creates a new ring buffer with power-of-2 size
func NewRingBuffer(size int) *RingBuffer {
	// Ensure size is power of 2 for efficient masking
	actualSize := 1
	for actualSize < size {
		actualSize <<= 1
	}

	return &RingBuffer{
		buffer: make([]byte, actualSize),
		size:   int64(actualSize),
		mask:   int64(actualSize - 1),
	}
}

// Write appends data to the ring buffer
func (rb *RingBuffer) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	available := rb.size - (rb.writePos - rb.readPos)
	if int64(len(data)) > available {
		return 0, ErrRingBufferFull
	}

	written := 0
	for written < len(data) {
		pos := rb.writePos & rb.mask
		endPos := rb.size
		if pos+int64(len(data)-written) < rb.size {
			endPos = pos + int64(len(data)-written)
		}

		copyLen := int(endPos - pos)
		copy(rb.buffer[pos:endPos], data[written:written+copyLen])
		written += copyLen
		rb.writePos += int64(copyLen)
	}

	return written, nil
}

// Read extracts data from the ring buffer
func (rb *RingBuffer) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}

	rb.mu.RLock()
	defer rb.mu.RUnlock()

	available := rb.writePos - rb.readPos
	if available == 0 {
		return 0, ErrRingBufferEmpty
	}

	toRead := int64(len(data))
	if toRead > available {
		toRead = available
	}

	read := int64(0)
	for read < toRead {
		pos := rb.readPos & rb.mask
		endPos := rb.size
		if pos+toRead-read < rb.size {
			endPos = pos + toRead - read
		}

		copyLen := int(endPos - pos)
		copy(data[read:read+int64(copyLen)], rb.buffer[pos:endPos])
		read += int64(copyLen)
		rb.readPos += int64(copyLen)
	}

	return int(read), nil
}

// Available returns the number of bytes available for reading
func (rb *RingBuffer) Available() int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.writePos - rb.readPos
}

// Capacity returns the total capacity of the ring buffer
func (rb *RingBuffer) Capacity() int64 {
	return rb.size
}

// Free returns the number of bytes available for writing
func (rb *RingBuffer) Free() int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size - (rb.writePos - rb.readPos)
}

// Reset clears the ring buffer
func (rb *RingBuffer) Reset() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.readPos = 0
	rb.writePos = 0
}

// Errors
var (
	ErrRingBufferFull  = fmt.Errorf("ring buffer is full")
	ErrRingBufferEmpty = fmt.Errorf("ring buffer is empty")
)
