package multiplex

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
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

// responseQueue overlaps codec reads with demultiplexing once per carrier.
// Its completion channel publishes the source cause after buffered data drains.
type responseQueue struct {
	*pipe.Reader
	cancel    context.CancelFunc
	completed chan error
	terminal  error
}

func (q *responseQueue) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if q.terminal != nil {
		return nil, q.terminal
	}
	mb, err := q.Reader.ReadMultiBuffer()
	if err == io.EOF {
		q.terminal = <-q.completed
		if q.terminal == nil {
			q.terminal = io.EOF
		}
		err = q.terminal
	}
	return mb, err
}

func (q *responseQueue) Interrupt() { q.Reader.Interrupt(); q.cancel() }

// OpenLink installs one immutable owner after VLESS codec preparation.
func OpenLink(ctx context.Context, cancel context.CancelFunc, conn stat.Connection, writer buf.Writer, activity *signal.ActivityTimer, receiveLimit int32, openResponse func() (buf.Reader, error)) (*transport.Link, error) {
	gate, ok := writer.(*buf.BufferedWriter)
	if !ok {
		gate = buf.NewBufferedWriter(WrapWriter(ctx, cancel, writer, activity))
		gate.SetBuffered(false)
	}
	queueReader, queueWriter := pipe.New(pipe.WithSizeLimit(receiveLimit))
	queue := &responseQueue{Reader: queueReader, cancel: cancel, completed: make(chan error, 1)}
	context.AfterFunc(ctx, func() {
		queueReader.Interrupt()
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
		body, err := openResponse()
		if err == nil {
			err = buf.Copy(body, queueWriter, buf.UpdateActivity(activity))
		}
		queue.completed <- err
		queueWriter.Close()
	}()
	return &transport.Link{Reader: queue, Writer: gate}, nil
}
