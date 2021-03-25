package dispatcher

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type Bucket struct {
	Writer  buf.Writer
	Limiter *rate.Limiter
}

// WriteMultiBuffer writes a MultiBuffer into underlying writer.
func (w *Bucket) WriteMultiBuffer(mb buf.MultiBuffer) error {
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(500*time.Millisecond))
	err := w.Limiter.WaitN(ctx, int(mb.Len())/4)
	if err != nil {
		return newError("waiting to get a new ticket").AtDebug()
	}

	return w.Writer.WriteMultiBuffer(mb)
}

// Close WriteBuffer
func (w *Bucket) Close() error {
	return common.Close(w.Writer)
}

func (w *Bucket) Interrupt() {
	common.Interrupt(w.Writer)
}
