package reverse

import (
	"context"
	"time"

	"github.com/hosemorinho412/xray-core/common/errors"
	"github.com/hosemorinho412/xray-core/common/mux"
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/common/session"
	"github.com/hosemorinho412/xray-core/common/task"
	"github.com/hosemorinho412/xray-core/features/routing"
	"github.com/hosemorinho412/xray-core/transport"
	"github.com/hosemorinho412/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

// Bridge is a component in reverse proxy, that relays connections from Portal to local address.
type Bridge struct {
	dispatcher  routing.Dispatcher
	tag         string
	domain      string
	workers     []*BridgeWorker
	monitorTask *task.Periodic
}

// NewBridge creates a new Bridge instance.
func NewBridge(config *BridgeConfig, dispatcher routing.Dispatcher) (*Bridge, error) {
	if config.Tag == "" {
		return nil, errors.New("bridge tag is empty")
	}
	if config.Domain == "" {
		return nil, errors.New("bridge domain is empty")
	}

	b := &Bridge{
		dispatcher: dispatcher,
		tag:        config.Tag,
		domain:     config.Domain,
	}
	b.monitorTask = &task.Periodic{
		Execute:  b.monitor,
		Interval: time.Second * 2,
	}
	return b, nil
}

func (b *Bridge) cleanup() {
	var activeWorkers []*BridgeWorker

	for _, w := range b.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}

	if len(activeWorkers) != len(b.workers) {
		b.workers = activeWorkers
	}
}

func (b *Bridge) monitor() error {
	b.cleanup()

	var numConnections uint32
	var numWorker uint32

	for _, w := range b.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}

	if numWorker == 0 || numConnections/numWorker > 16 {
		worker, err := NewBridgeWorker(b.domain, b.tag, b.dispatcher)
		if err != nil {
			errors.LogWarningInner(context.Background(), err, "failed to create bridge worker")
			return nil
		}
		b.workers = append(b.workers, worker)
	}

	return nil
}

func (b *Bridge) Start() error {
	return b.monitorTask.Start()
}

func (b *Bridge) Close() error {
	return b.monitorTask.Close()
}

type BridgeWorker struct {
	tag        string
	worker     *mux.ServerWorker
	dispatcher routing.Dispatcher
	state      Control_State
}

func NewBridgeWorker(domain string, tag string, d routing.Dispatcher) (*BridgeWorker, error) {
	ctx := context.Background()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Tag: tag,
	})
	link, err := d.Dispatch(ctx, net.Destination{
		Network: net.Network_TCP,
		Address: net.DomainAddress(domain),
		Port:    0,
	})
	if err != nil {
		return nil, err
	}

	w := &BridgeWorker{
		dispatcher: d,
		tag:        tag,
	}

	worker, err := mux.NewServerWorker(context.Background(), w, link)
	if err != nil {
		return nil, err
	}
	w.worker = worker

	return w, nil
}

func (w *BridgeWorker) Type() interface{} {
	return routing.DispatcherType()
}

func (w *BridgeWorker) Start() error {
	return nil
}

func (w *BridgeWorker) Close() error {
	return nil
}

func (w *BridgeWorker) IsActive() bool {
	return w.state == Control_ACTIVE && !w.worker.Closed()
}

func (w *BridgeWorker) Connections() uint32 {
	return w.worker.ActiveConnections()
}

func (w *BridgeWorker) handleInternalConn(link *transport.Link) {
	go func() {
		reader := link.Reader
		for {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				break
			}
			for _, b := range mb {
				var ctl Control
				if err := proto.Unmarshal(b.Bytes(), &ctl); err != nil {
					errors.LogInfoInner(context.Background(), err, "failed to parse proto message")
					break
				}
				if ctl.State != w.state {
					w.state = ctl.State
				}
			}
		}
	}()
}

func (w *BridgeWorker) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	if !isInternalDomain(dest) {
		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Tag: w.tag,
		})
		return w.dispatcher.Dispatch(ctx, dest)
	}

	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	w.handleInternalConn(&transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	})

	return &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}, nil
}

func (w *BridgeWorker) DispatchLink(ctx context.Context, dest net.Destination, link *transport.Link) error {
	if !isInternalDomain(dest) {
		ctx = session.ContextWithInbound(ctx, &session.Inbound{
			Tag: w.tag,
		})
		return w.dispatcher.DispatchLink(ctx, dest, link)
	}

	w.handleInternalConn(link)

	return nil
}
