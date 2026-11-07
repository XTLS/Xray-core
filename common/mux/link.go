package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

// singleWriter returns a writer that all goroutines of one mux worker can
// share. Every session writes its frames from its own goroutine, and the
// worker writes keepalive and end frames from others, while the writer of
// the connection below (VisionWriter, the VLESS body writer, a cipher)
// keeps state between calls and must see one call at a time, in the order
// its output goes out. A pipe is already such a writer: it takes whole
// frames under its own lock and only its reader touches what is behind it.
// Any other writer gets a pipe in front of it and one goroutine that copies
// the pipe into it, which is what the mux had before VLESS started to hand
// its connection writer to the mux directly.
func singleWriter(w buf.Writer) buf.Writer {
	if _, ok := w.(*pipe.Writer); ok {
		return w
	}
	r, pw := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
	go func() {
		if err := buf.Copy(r, w); err != nil {
			common.Interrupt(r) // the next write of any session fails
		}
		common.Interrupt(w)
	}()
	return pw
}
