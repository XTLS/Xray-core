package encoding_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
)

func TestMultiLengthPacketWriter(t *testing.T) {
	for _, c := range []struct {
		sizes   []int32
		buffers int
	}{
		{[]int32{1200}, 1},
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200}, 1}, // was 6
		{[]int32{1200, 1200, 1200, 1200, 1200, 1200, 1200}, 2},
		{[]int32{4094, 4094}, 1}, // 2 * (2 + 4094) = 8192 bytes
		{[]int32{4095, 4095}, 2},
		{[]int32{8190}, 1},
		{[]int32{8191}, 0}, // too large, as before
	} {
		var m buf.MultiBufferContainer
		var mb buf.MultiBuffer
		for i, size := range c.sizes {
			b := buf.New()
			b.Write(bytes.Repeat([]byte{byte(i + 1)}, int(size)))
			mb = append(mb, b)
		}
		common.Must(NewMultiLengthPacketWriter(&m).WriteMultiBuffer(mb))
		if len(m.MultiBuffer) != c.buffers {
			t.Errorf("%v: %d Buffers, want %d", c.sizes, len(m.MultiBuffer), c.buffers)
		}

		reader := NewLengthPacketReader(&m)
		for i, size := range c.sizes {
			if size+2 > buf.Size {
				continue
			}
			mb, err := reader.ReadMultiBuffer()
			common.Must(err)
			if len(mb) != 1 || !bytes.Equal(mb[0].Bytes(), bytes.Repeat([]byte{byte(i + 1)}, int(size))) {
				t.Errorf("%v: packet %d came out wrong", c.sizes, i)
			}
			buf.ReleaseMulti(mb)
		}
	}
}
