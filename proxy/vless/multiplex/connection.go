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

// readResult transfers one native decoded result, including its exact cause.
type readResult struct {
	data buf.MultiBuffer
	err  error
}

type responseReader struct {
	ctx      context.Context
	cancel   context.CancelFunc
	results  chan readResult
	terminal error
}

func (r *responseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.terminal != nil {
		return nil, r.terminal
	}
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case result := <-r.results:
		if err := r.ctx.Err(); err != nil {
			buf.ReleaseMulti(result.data)
			return nil, err
		}
		r.terminal = result.err
		// BufferedReader.Read ignores data returned alongside an error.
		if !result.data.IsEmpty() {
			return result.data, nil
		}
		return result.data, r.terminal
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
	response := &responseReader{ctx: ctx, cancel: cancel, results: make(chan readResult)}
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
		if ctx.Err() != nil {
			return
		}
		body, err := openResponse()
		for {
			var data buf.MultiBuffer
			if err == nil {
				if ctx.Err() != nil {
					return
				}
				data, err = body.ReadMultiBuffer()
			}
			if !data.IsEmpty() {
				activity.Update()
			} else {
				data = buf.ReleaseMulti(data)
				if err == nil {
					continue
				}
			}
			select {
			case response.results <- readResult{data: data, err: err}:
			case <-ctx.Done():
				buf.ReleaseMulti(data)
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return &transport.Link{Reader: response, Writer: gate}, nil
}
