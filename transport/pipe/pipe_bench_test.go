package pipe_test

import (
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

func BenchmarkPipeReadWriteContention(b *testing.B) {
	pReader, pWriter := New(WithoutSizeLimit())
	payload := buf.New()
	common.Must2(payload.Write(make([]byte, 1024)))

	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				rb, err := pReader.ReadMultiBuffer()
				if err != nil {
					return
				}
				buf.ReleaseMulti(rb)
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		common.Must(pWriter.WriteMultiBuffer(buf.MultiBuffer{payload}))
	}
	close(done)
}
