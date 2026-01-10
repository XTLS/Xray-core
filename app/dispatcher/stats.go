package dispatcher

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// SizeStatWriter wraps a buf.Writer with only size counting (no rate limiting)
type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// SizeStatReader wraps a buf.Reader with only size counting (no rate limiting)
type SizeStatReader struct {
	Counter stats.Counter
	Reader  buf.Reader
}

func (r *SizeStatReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	r.Counter.Add(int64(mb.Len()))
	return mb, err
}

func (r *SizeStatReader) Close() error {
	return common.Close(r.Reader)
}

func (r *SizeStatReader) Interrupt() {
	common.Interrupt(r.Reader)
}
