package multiplex

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

// PhysicalWriter owns native output serialization without buffering data.
type PhysicalWriter struct {
	sync.Mutex
	buf.Writer
}

func (w *PhysicalWriter) Close() error { return common.Close(w.Writer) }
func (w *PhysicalWriter) Interrupt()   { common.Interrupt(w.Writer) }

type activityWriter struct {
	ctx      context.Context
	writer   buf.Writer
	activity *signal.ActivityTimer
}

func WrapWriter(ctx context.Context, writer buf.Writer, activity *signal.ActivityTimer) buf.Writer {
	return &activityWriter{ctx: ctx, writer: writer, activity: activity}
}

func (w *activityWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	if err := w.ctx.Err(); err != nil {
		buf.ReleaseMulti(data)
		return err
	}
	if !data.IsEmpty() {
		w.activity.Update()
	}
	return w.writer.WriteMultiBuffer(data)
}

type responseReader struct {
	ctx     context.Context
	cancel  context.CancelFunc
	results chan buf.MultiBuffer
	// The producer publishes terminal before closing results.
	terminal error
}

func (r *responseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case data, ok := <-r.results:
		if err := r.ctx.Err(); err != nil {
			buf.ReleaseMulti(data)
			return nil, err
		}
		if !ok {
			return nil, r.terminal
		}
		return data, nil
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}
}

func (r *responseReader) Interrupt() { r.cancel() }

// OpenLink retains decoded read-ahead; the carrier owns output serialization.
func OpenLink(ctx context.Context, cancel context.CancelFunc, writer buf.Writer, activity *signal.ActivityTimer, openResponse func() (buf.Reader, error)) (*transport.Link, error) {
	if _, buffered := writer.(*buf.BufferedWriter); !buffered {
		writer = WrapWriter(ctx, writer, activity)
	}
	response := &responseReader{ctx: ctx, cancel: func() {
		cancel()
		activity.SetTimeout(0)
	}, results: make(chan buf.MultiBuffer)}
	if err := ctx.Err(); err != nil {
		response.Interrupt()
		return nil, err
	}
	go func() {
		err := ctx.Err()
		defer func() {
			response.terminal = err
			close(response.results)
		}()
		if err != nil {
			return
		}
		body, err := openResponse()
		for err == nil {
			if err = ctx.Err(); err != nil {
				return
			}
			var data buf.MultiBuffer
			data, err = body.ReadMultiBuffer()
			if data.IsEmpty() {
				buf.ReleaseMulti(data)
				continue
			}
			activity.Update()
			select {
			case response.results <- data:
			case <-ctx.Done():
				buf.ReleaseMulti(data)
				err = ctx.Err()
				return
			}
		}
	}()
	return &transport.Link{Reader: response, Writer: writer}, nil
}
