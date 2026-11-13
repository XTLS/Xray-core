package reverse

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

// Bridge is a component in reverse proxy, that relays connections from Portal to local address.
type Bridge struct {
	ctx         context.Context
	cancel      context.CancelFunc
	open        func(context.Context) (context.Context, *transport.Link, error)
	access      sync.Mutex
	dispatcher  routing.Dispatcher
	tag         string
	workers     []*BridgeWorker
	monitorTask *task.Periodic
}

func NewBridge(ctx context.Context, tag string, dispatcher routing.Dispatcher, open func(context.Context) (context.Context, *transport.Link, error)) *Bridge {
	b := &Bridge{tag: tag, dispatcher: dispatcher, open: open}
	b.ctx, b.cancel = context.WithCancel(ctx)
	b.monitorTask = &task.Periodic{Execute: b.monitor, Interval: 2 * time.Second}
	return b
}

func (b *Bridge) monitor() error {
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.ctx.Err(); err != nil {
		return err
	}
	var numConnections uint32
	active := b.workers[:0]
	for _, w := range b.workers {
		if w.IsActive() {
			active = append(active, w)
			numConnections += w.Connections()
		}
	}
	clear(b.workers[len(active):])
	b.workers = active
	numWorker := uint32(len(b.workers))

	if numWorker == 0 || numConnections/numWorker > 16 {
		worker, err := b.newWorker()
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "failed to create bridge worker")
			return nil
		}
		b.workers = append(b.workers, worker)
	}

	return nil
}

func (b *Bridge) newWorker() (*BridgeWorker, error) {
	ctx, link, err := b.open(b.ctx)
	if err != nil {
		return nil, err
	}
	w := &BridgeWorker{Tag: b.tag, dispatch: b.dispatcher.DispatchLink}
	w.Worker = multiplex.NewServerWorker(session.ContextWithIsReverseMultiplex(ctx, true), w.handle, link)
	return w, nil
}

func (b *Bridge) Start() error {
	if err := b.ctx.Err(); err != nil {
		return err
	}
	return b.monitorTask.Start()
}

func (b *Bridge) Close() error {
	b.cancel()
	err := b.monitorTask.Close()
	b.access.Lock()
	defer b.access.Unlock()
	for _, w := range b.workers {
		w.Worker.Close()
	}
	return err
}

type BridgeWorker struct {
	Tag      string
	Worker   *multiplex.ServerWorker
	dispatch func(context.Context, net.Destination, *transport.Link) error
	State    atomic.Int32
}

func (w *BridgeWorker) IsActive() bool {
	return w.State.Load() == int32(Control_ACTIVE) && !w.Worker.Closed()
}

func (w *BridgeWorker) Closed() bool {
	return w.Worker.Closed()
}

func (w *BridgeWorker) Connections() uint32 {
	return w.Worker.ActiveConnections()
}

// handle forwards user traffic or consumes the native Reverse control stream.
func (w *BridgeWorker) handle(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if !isInternalDomain(dest) {
		if session.InboundFromContext(ctx) == nil {
			ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag: w.Tag})
		}
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
			w.State.Store(int32(ctl.State))
		}
		buf.ReleaseMulti(mb)
		if readErr != nil {
			return nil
		}
	}
}
