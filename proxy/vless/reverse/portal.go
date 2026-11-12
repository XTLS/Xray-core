package reverse

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

type Portal struct {
	observer features.Feature
	tag      string
	picker   *StaticPicker
}

func NewPortal(tag string, observer features.Feature) *Portal {
	picker := NewStaticPicker()
	return &Portal{tag: tag, observer: observer, picker: picker}
}

func (p *Portal) Tag() string                          { return p.tag }
func (p *Portal) SenderSettings() *serial.TypedMessage { return nil }
func (p *Portal) ProxySettings() *serial.TypedMessage  { return nil }
func (p *Portal) Dispatch(ctx context.Context, link *transport.Link) {
	if err := p.HandleConnection(ctx, link); err != nil {
		errors.LogInfoInner(ctx, err, "failed to process reverse connection")
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
}

func (p *Portal) Accept(ctx context.Context, link *transport.Link) error {
	client := multiplex.NewClientWorker(*link, multiplex.ClientStrategy{})
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	worker, err := NewPortalWorker(client)
	if err != nil {
		client.Close()
		return errors.New("failed to create portal worker").Base(err)
	}
	defer func() {
		p.picker.RemoveWorker(worker)
		worker.Close()
	}()
	p.picker.AddWorker(worker)
	if observer, ok := p.observer.(extension.BurstObservatory); ok {
		go observer.Check([]string{p.tag})
	}
	select {
	case <-ctx.Done():
	case <-client.WaitClosed():
	}
	return nil
}

func (p *Portal) Start() error {
	return nil
}

func (p *Portal) Close() error {
	p.picker.Close()
	return nil
}

func (p *Portal) HandleConnection(ctx context.Context, link *transport.Link) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return errors.New("outbound metadata not found")
	}

	ctx = session.ContextWithIsReverseMux(ctx, true)

	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}

	return multiplex.Dispatch(ctx, link, true, p.picker.PickAvailable)
}

type StaticPicker struct {
	closed  bool
	access  sync.Mutex
	workers []*PortalWorker
}

func NewStaticPicker() *StaticPicker {
	return &StaticPicker{}
}

func (p *StaticPicker) PickAvailable(context.Context) (*multiplex.ClientWorker, error) {
	p.access.Lock()
	defer p.access.Unlock()

	if p.closed || len(p.workers) == 0 {
		return nil, errors.New("empty worker list")
	}

	var minIdx int = -1
	var minConn uint32 = 9999
	for i, w := range p.workers {
		if w.draining.Load() {
			continue
		}
		if w.IsFull() {
			continue
		}
		if w.client.ActiveConnections() < minConn {
			minConn = w.client.ActiveConnections()
			minIdx = i
		}
	}

	if minIdx == -1 {
		for i, w := range p.workers {
			if w.IsFull() {
				continue
			}
			if w.client.ActiveConnections() < minConn {
				minConn = w.client.ActiveConnections()
				minIdx = i
			}
		}
	}

	if minIdx != -1 {
		return p.workers[minIdx].client, nil
	}

	return nil, errors.New("no mux client worker available")
}

func (p *StaticPicker) AddWorker(worker *PortalWorker) {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		worker.Close()
		return
	}
	p.workers = append(p.workers, worker)
	p.access.Unlock()
}

func (p *StaticPicker) RemoveWorker(worker *PortalWorker) {
	p.access.Lock()
	defer p.access.Unlock()
	p.workers = slices.DeleteFunc(p.workers, func(current *PortalWorker) bool { return current == worker })
}

func (p *StaticPicker) Close() {
	p.access.Lock()
	p.closed = true
	workers := p.workers
	p.workers = nil
	p.access.Unlock()
	for _, worker := range workers {
		worker.Close()
	}
}

type PortalWorker struct {
	client   *multiplex.ClientWorker
	control  *task.Periodic
	writer   buf.Writer
	draining atomic.Bool
	counter  uint32
	timer    *signal.ActivityTimer
}

func NewPortalWorker(client *multiplex.ClientWorker) (*PortalWorker, error) {
	ctx := context.Background()
	writer, err := client.NewPacketWriter(net.UDPDestination(net.DomainAddress(internalDomain), 0))
	if err != nil {
		return nil, err
	}
	terminate := func() {
		client.Close()
	}
	w := &PortalWorker{
		client: client,
		writer: writer,
		timer:  signal.CancelAfterInactivity(ctx, terminate, 24*time.Hour), // // prevent leak
	}
	w.control = &task.Periodic{
		Execute:  w.heartbeat,
		Interval: time.Second * 2,
	}
	w.control.Start()
	return w, nil
}

func (w *PortalWorker) Close() {
	w.client.Close()
	w.control.Close()
	w.timer.SetTimeout(0)
}

func (w *PortalWorker) heartbeat() error {
	if w.Closed() {
		return errors.New("client worker stopped")
	}

	if w.draining.Load() || w.writer == nil {
		return errors.New("already disposed")
	}

	msg := &Control{}
	msg.FillInRandom()

	if w.client.TotalConnections() > 256 {
		w.draining.Store(true)
		msg.State = Control_DRAIN

		defer func() {
			common.Close(w.writer)
			w.writer = nil
		}()
	}

	w.counter = (w.counter + 1) % 5
	if w.draining.Load() || w.counter == 1 {
		b, err := proto.Marshal(msg)
		common.Must(err)
		mb := buf.MergeBytes(nil, b)
		w.timer.Update()
		return w.writer.WriteMultiBuffer(mb)
	}
	return nil
}

func (w *PortalWorker) IsFull() bool {
	return w.client.IsFull()
}

func (w *PortalWorker) Closed() bool {
	return w.client.Closed()
}
