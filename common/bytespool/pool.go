package bytespool

import "sync"

// Sizes of the buffer pools.
// Package buf is guaranteed to not use buffers larger than the largest pool.
// Other packets may use larger buffers.
const (
	size2k   = 2048
	size8k   = 8192
	size32k  = 32768
	size128k = 131072
)

// GetPool pools hold []byte, as its callers expect.
var (
	poolSize = [...]int32{size2k, size8k, size32k, size128k}
	pool     [len(poolSize)]sync.Pool
)

func init() {
	for i, size := range poolSize {
		pool[i].New = func() any { return make([]byte, size) }
	}
}

// GetPool returns a sync.Pool that generates bytes array with at least the given size.
// It may return nil if no such pool exists.
//
// xray:api:stable
func GetPool(size int32) *sync.Pool {
	for idx, ps := range poolSize {
		if size <= ps {
			return &pool[idx]
		}
	}
	return nil
}

// Alloc and Free pools hold array pointers: unlike a slice, a pointer goes into
// a sync.Pool without an allocation.
var (
	arrays2k   = sync.Pool{New: func() any { return new([size2k]byte) }}
	arrays8k   = sync.Pool{New: func() any { return new([size8k]byte) }}
	arrays32k  = sync.Pool{New: func() any { return new([size32k]byte) }}
	arrays128k = sync.Pool{New: func() any { return new([size128k]byte) }}
)

// Alloc returns a byte slice with at least the given size. Minimum size of returned slice is 2048.
//
// xray:api:stable
func Alloc(size int32) []byte {
	switch {
	case size <= size2k:
		return arrays2k.Get().(*[size2k]byte)[:]
	case size <= size8k:
		return arrays8k.Get().(*[size8k]byte)[:]
	case size <= size32k:
		return arrays32k.Get().(*[size32k]byte)[:]
	case size <= size128k:
		return arrays128k.Get().(*[size128k]byte)[:]
	}
	return make([]byte, size)
}

// Free puts a byte slice into the internal pool.
//
// xray:api:stable
func Free(b []byte) {
	switch c := cap(b); {
	case c >= size128k:
		arrays128k.Put((*[size128k]byte)(b[:size128k]))
	case c >= size32k:
		arrays32k.Put((*[size32k]byte)(b[:size32k]))
	case c >= size8k:
		arrays8k.Put((*[size8k]byte)(b[:size8k]))
	case c >= size2k:
		arrays2k.Put((*[size2k]byte)(b[:size2k]))
	}
}
