package mux

import (
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

// lockedWriter serializes complete frames from concurrent mux sessions.
type lockedWriter struct {
	access sync.Mutex
	writer buf.Writer
}

func newMuxWriter(writer buf.Writer) buf.Writer {
	return &lockedWriter{writer: writer}
}

func (w *lockedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.access.Lock()
	defer w.access.Unlock()
	return w.writer.WriteMultiBuffer(mb)
}

// Shutdown must not wait for a blocked write to release access.
func (w *lockedWriter) Interrupt() {
	_ = common.Interrupt(w.writer)
}

func (w *lockedWriter) Close() error {
	return common.Close(w.writer)
}
