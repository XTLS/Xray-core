package multiplex

import (
	"context"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport"
)

type responseReader struct {
	ctx      context.Context
	cancel   context.CancelFunc
	activity *signal.ActivityTimer
	open     func() (buf.Reader, error)
	body     buf.Reader
	terminal error
}

func (r *responseReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	if r.open != nil {
		r.body, r.terminal = r.open()
		r.open = nil
	}
	for r.terminal == nil {
		data, err := r.body.ReadMultiBuffer()
		r.terminal = err
		if err := r.ctx.Err(); err != nil {
			buf.ReleaseMulti(data)
			return nil, err
		}
		if !data.IsEmpty() {
			r.activity.Update()
			return data, nil
		}
		buf.ReleaseMulti(data)
	}
	return nil, r.terminal
}

func (r *responseReader) Interrupt() {
	r.cancel()
	r.activity.SetTimeout(0)
}

func OpenLink(ctx context.Context, cancel context.CancelFunc, writer buf.Writer, activity *signal.ActivityTimer, openResponse func() (buf.Reader, error)) (*transport.Link, error) {
	if err := ctx.Err(); err != nil {
		cancel()
		activity.SetTimeout(0)
		return nil, err
	}
	return &transport.Link{Reader: &responseReader{ctx: ctx, cancel: cancel, activity: activity, open: openResponse}, Writer: writer}, nil
}
