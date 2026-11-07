package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// mux sessions write concurrently, so only one goroutine should write to w
func singleWriter(w buf.Writer) buf.Writer {
	if _, ok := w.(*pipe.Writer); ok {
		return w
	}
	r, pw := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
	go func() {
		if err := buf.Copy(r, w); err != nil {
			common.Interrupt(r)
		}
		common.Interrupt(w)
	}()
	return pw
}
