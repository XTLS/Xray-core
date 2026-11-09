package mux_test

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport/pipe"
)

// A worker ends its link with common.Interrupt and common.Close on the
// MutexWriter around it: both must reach the writer inside, or the link
// stays open after the worker is gone.
func TestMutexWriterPassesInterruptAndClose(t *testing.T) {
	for name, end := range map[string]func(any) error{
		"interrupt": func(w any) error { return common.Interrupt(w) },
		"close":     func(w any) error { return common.Close(w) },
	} {
		r, w := pipe.New()
		common.Must(end(&mux.MutexWriter{Writer: w}))
		if _, err := r.ReadMultiBufferTimeout(time.Second); err != io.EOF && err != io.ErrClosedPipe {
			t.Errorf("%s: read after it got %v, want the pipe ended", name, err)
		}
	}
}

// A write stuck on a peer that stopped reading holds the lock: an interrupt
// must not wait for it.
func TestMutexWriterInterruptsStuckWrite(t *testing.T) {
	_, w := pipe.New(pipe.WithSizeLimit(0))
	mw := &mux.MutexWriter{Writer: w}
	byte1 := func() buf.MultiBuffer {
		b := buf.New()
		b.Extend(1)
		return buf.MultiBuffer{b}
	}
	// The pipe is full past its limit: the next write waits for a reader.
	common.Must(mw.WriteMultiBuffer(byte1()))
	done := make(chan error, 1)
	go func() { done <- mw.WriteMultiBuffer(byte1()) }()
	time.Sleep(50 * time.Millisecond)
	common.Interrupt(mw)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stuck write returned no error after an interrupt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("interrupt did not reach a write stuck under the lock")
	}
}
