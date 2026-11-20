package reverse

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

// StartIntranet maintains Reverse carriers until the returned cancellation function is called.
// The opener derives each physical connection's context from the supplied context.
func StartIntranet(ctx context.Context, dispatch func(context.Context, net.Destination, *transport.Link) error, open func(context.Context) (context.Context, *transport.Link, error)) func() {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		const interval = 2 * time.Second
		timer := time.NewTimer(interval)
		defer timer.Stop()
		var workers []*intranetWorker
		for ; ; timer.Reset(interval) {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			if ctx.Err() != nil {
				return
			}
			var connections uint32
			active := workers[:0]
			for _, w := range workers {
				if w.state.Load() == int32(Control_ACTIVE) && !w.worker.Closed() {
					active = append(active, w)
					connections += w.worker.ActiveConnections()
				}
			}
			clear(workers[len(active):])
			workers = active
			if len(workers) != 0 && connections/uint32(len(workers)) <= 16 {
				continue
			}
			physical, link, err := open(ctx)
			if err != nil {
				errors.LogWarningInner(ctx, err, "failed to create intranet worker")
				continue
			}
			w := &intranetWorker{dispatch: dispatch}
			w.worker = multiplex.NewServerWorker(session.ContextWithIsReverseMux(physical, true), w.handle, link)
			workers = append(workers, w)
		}
	}()
	return cancel
}

type intranetWorker struct {
	worker   *multiplex.ServerWorker
	dispatch func(context.Context, net.Destination, *transport.Link) error
	state    atomic.Int32
}

// handle forwards user traffic or consumes the native Reverse control stream.
func (w *intranetWorker) handle(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if !isInternalDomain(dest) {
		return w.dispatch(ctx, dest, link)
	}
	defer common.Close(link.Writer)
	defer common.Interrupt(link.Reader)
	for {
		mb, readErr := link.Reader.ReadMultiBuffer()
		for _, b := range mb {
			var ctl Control
			if err := proto.Unmarshal(b.Bytes(), &ctl); err != nil {
				buf.ReleaseMulti(mb)
				errors.LogInfoInner(ctx, err, "failed to parse proto message")
				return nil
			}
			w.state.Store(int32(ctl.State))
		}
		buf.ReleaseMulti(mb)
		if readErr != nil {
			return nil
		}
	}
}
