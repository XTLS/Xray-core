package buf_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

func BenchmarkSniffBufferPool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b := GetSniffBuffer()
		PutSniffBuffer(b)
	}
}

func BenchmarkSniffBufferNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b := NewWithSize(SniffBufferSize)
		b.Release()
	}
}
