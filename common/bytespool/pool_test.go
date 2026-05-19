package bytespool_test

import (
	"testing"

	"github.com/xtls/xray-core/common/bytespool"
)

func TestGetPool(t *testing.T) {
	if bytespool.GetPool(1024) == nil {
		t.Fatal("expected pool for 1024 bytes")
	}
	if bytespool.GetPool(1<<20) != nil {
		t.Fatal("expected nil pool for oversized allocation")
	}
}

func TestAllocFreeRoundTrip(t *testing.T) {
	b := bytespool.Alloc(8192)
	if cap(b) < 8192 {
		t.Fatalf("alloc cap %d want >= 8192", cap(b))
	}
	b[0] = 0xab
	bytespool.Free(b)

	b2 := bytespool.Alloc(8192)
	if cap(b2) < 8192 {
		t.Fatalf("realloc cap %d want >= 8192", cap(b2))
	}
	bytespool.Free(b2)
}

func TestFreeSizeBucketing(t *testing.T) {
	sizes := []int32{2048, 8192, 32768}
	for _, size := range sizes {
		b := bytespool.Alloc(size)
		if cap(b) < int(size) {
			t.Fatalf("size %d: cap %d", size, cap(b))
		}
		bytespool.Free(b)
	}
}
