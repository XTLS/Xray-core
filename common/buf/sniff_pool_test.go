package buf_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
)

func TestSniffBufferPool(t *testing.T) {
	b1 := GetSniffBuffer()
	if b1.Cap() < SniffBufferSize {
		t.Fatalf("cap %d want >= %d", b1.Cap(), SniffBufferSize)
	}
	common.Must2(b1.Write([]byte{1}))
	PutSniffBuffer(b1)

	b2 := GetSniffBuffer()
	if !b2.IsEmpty() {
		t.Fatal("expected cleared buffer from pool")
	}
	PutSniffBuffer(b2)
}
