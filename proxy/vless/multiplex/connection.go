package multiplex

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type activityWriter struct {
	ctx      context.Context
	cancel   context.CancelFunc
	writer   buf.Writer
	activity *signal.ActivityTimer
}

func WrapWriter(ctx context.Context, cancel context.CancelFunc, writer buf.Writer, activity *signal.ActivityTimer) buf.Writer {
	return &activityWriter{ctx: ctx, cancel: cancel, writer: writer, activity: activity}
}

func (w *activityWriter) WriteMultiBuffer(data buf.MultiBuffer) error {
	if err := w.ctx.Err(); err != nil {
		buf.ReleaseMulti(data)
		return err
	}
	if !data.IsEmpty() {
		w.activity.Update()
	}
	err := w.writer.WriteMultiBuffer(data)
	if err != nil {
		w.cancel()
	}
	return err
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

// OpenLink installs one immutable owner after VLESS codec preparation.
func OpenLink(ctx context.Context, cancel context.CancelFunc, conn stat.Connection, writer buf.Writer, activity *signal.ActivityTimer, openResponse func() (buf.Reader, error)) (*transport.Link, error) {
	gate, ok := writer.(*buf.BufferedWriter)
	if !ok {
		gate = buf.NewBufferedWriter(WrapWriter(ctx, cancel, writer, activity))
		gate.SetBuffered(false)
	}
	response := &responseReader{ctx: ctx, cancel: cancel, results: make(chan buf.MultiBuffer)}
	context.AfterFunc(ctx, func() {
		activity.SetTimeout(0)
		if gate.TryLock() {
			gate.Unlock()
			conn.Close()
		} else {
			common.Interrupt(stat.TryUnwrapStatsConn(conn))
		}
	})
	if err := ctx.Err(); err != nil {
		activity.SetTimeout(0)
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
	return &transport.Link{Reader: response, Writer: gate}, nil
}
