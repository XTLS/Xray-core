package dispatcher

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/features/stats"
)

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

// accessCounter keeps a local total while preserving the existing user counter.
type accessCounter struct {
	atomic.Int64
	user stats.Counter
}

func (c *accessCounter) Value() int64      { return c.Load() }
func (c *accessCounter) Set(v int64) int64 { return c.Swap(v) }
func (c *accessCounter) Add(v int64) int64 {
	if c.user != nil {
		c.user.Add(v)
	}
	return c.Int64.Add(v)
}

func (c *accessCounter) wrap(w buf.Writer) buf.Writer {
	if sw, ok := w.(*SizeStatWriter); ok {
		c.user, sw.Counter = sw.Counter, c
		return sw
	}
	return &SizeStatWriter{Writer: w, Counter: c}
}

type accessTraffic struct {
	up, down         accessCounter
	upDone, downDone <-chan struct{}
}

func newAccessTraffic(ctx context.Context) *accessTraffic {
	if log.AccessMessageFromContext(ctx) == nil || !log.AccessEnabled() {
		return nil
	}
	return new(accessTraffic)
}

// record takes a diagnostic snapshot at teardown. It does not wait for I/O
// still unwinding after an error. Pipe links may outlive Dispatch (Mux).
func (t *accessTraffic) record(message log.AccessMessage) {
	write := func() {
		message.Uplink, message.Downlink = t.up.Value(), t.down.Value()
		log.Record(&message)
	}
	if t.upDone == nil {
		write()
		return
	}
	go func() {
		<-t.upDone
		<-t.downDone
		write()
	}()
}
