package bytespool

import (
	"math/bits"
	"sync"
)

const (
	minShift = 10 // 1KB
	maxShift = 16 // 64KB
	numPools = maxShift - minShift + 1
	minSize  = 1 << minShift
	maxSize  = 1 << maxShift
)

// pools hold array pointers (*[N]byte) to avoid interface boxing allocations on Put.
var pools = [numPools]sync.Pool{
	{New: func() any { return new([1 << 10]byte) }},
	{New: func() any { return new([1 << 11]byte) }},
	{New: func() any { return new([1 << 12]byte) }},
	{New: func() any { return new([1 << 13]byte) }},
	{New: func() any { return new([1 << 14]byte) }},
	{New: func() any { return new([1 << 15]byte) }},
	{New: func() any { return new([1 << 16]byte) }},
}

// Alloc returns a byte slice with at least the given size. Minimum size of returned slice is 1024.
//
// xray:api:stable
func Alloc(size int32) []byte {
	if size > maxSize {
		return make([]byte, size)
	}
	index := 0
	if size > minSize {
		index = bits.Len32(uint32(size-1)) - minShift
	}
	p := pools[index].Get()
	switch index {
	case 0:
		return p.(*[1 << 10]byte)[:]
	case 1:
		return p.(*[1 << 11]byte)[:]
	case 2:
		return p.(*[1 << 12]byte)[:]
	case 3:
		return p.(*[1 << 13]byte)[:]
	case 4:
		return p.(*[1 << 14]byte)[:]
	case 5:
		return p.(*[1 << 15]byte)[:]
	case 6:
		return p.(*[1 << 16]byte)[:]
	default:
		panic("invalid pool index")
	}
}

// Free puts a byte slice into the internal pool.
//
// xray:api:stable
func Free(b []byte) {
	c := cap(b)
	if c < minSize || c > maxSize {
		return
	}
	index := bits.Len(uint(c)) - 1 - minShift
	switch index {
	case 0:
		pools[0].Put((*[1 << 10]byte)(b[:1<<10]))
	case 1:
		pools[1].Put((*[1 << 11]byte)(b[:1<<11]))
	case 2:
		pools[2].Put((*[1 << 12]byte)(b[:1<<12]))
	case 3:
		pools[3].Put((*[1 << 13]byte)(b[:1<<13]))
	case 4:
		pools[4].Put((*[1 << 14]byte)(b[:1<<14]))
	case 5:
		pools[5].Put((*[1 << 15]byte)(b[:1<<15]))
	case 6:
		pools[6].Put((*[1 << 16]byte)(b[:1<<16]))
	}
}
