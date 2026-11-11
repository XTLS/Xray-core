package reverse

import (
	"context"
	"sync"
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
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
	"google.golang.org/protobuf/proto"
)

type Portal struct {
	observer features.Feature
	ohm      outbound.Manager
	tag      string
	domain   string
	picker   *StaticPicker
	client   *multiplex.ClientManager
}

func newLegacyPortal(config *PortalConfig, ohm outbound.Manager) (*Portal, error) {
	if config.Tag == "" {
		return nil, errors.New("portal tag is empty")
	}

	if config.Domain == "" {
		return nil, errors.New("portal domain is empty")
	}

	p := NewPortal(config.Tag, nil)
	p.ohm = ohm
	p.domain = config.Domain
	return p, nil
}

func NewPortal(tag string, observer features.Feature) *Portal {
	picker := NewStaticPicker()
	return &Portal{tag: tag, observer: observer, picker: picker, client: &multiplex.ClientManager{Picker: picker}}
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
	client, err := multiplex.NewClientWorker(*link, multiplex.ClientStrategy{})
	if err != nil {
		return errors.New("failed to create multiplex client worker").Base(err)
	}
	worker, err := NewPortalWorker(client)
	if err != nil {
		client.Close()
		return errors.New("failed to create portal worker").Base(err)
	}
	p.picker.AddWorker(worker)
	if observer, ok := p.observer.(extension.BurstObservatory); ok {
		go observer.Check([]string{p.tag})
	}
	if _, ok := link.Reader.(*pipe.Reader); !ok || p.domain == "" {
		defer client.Close()
		select {
		case <-ctx.Done():
		case <-client.WaitClosed():
		}
	}
	return nil
}

func (p *Portal) Start() error {
	if p.ohm == nil {
		return nil
	}
	return p.ohm.AddHandler(context.Background(), &Outbound{
		Portal: p,
	})
}

func (p *Portal) Close() error {
	p.picker.Close()
	if p.ohm == nil {
		return nil
	}
	return p.ohm.RemoveHandler(context.Background(), p.tag)
}

func (p *Portal) HandleConnection(ctx context.Context, link *transport.Link) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return errors.New("outbound metadata not found")
	}

	if isDomain(ob.Target, p.domain) {
		return p.Accept(ctx, link)
	}
	if p.domain == "" {
		ctx = session.ContextWithIsReverseMux(ctx, true)
	}

	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}

	return p.client.Dispatch(ctx, link, false)
}

type Outbound struct {
	*Portal
}

func (o *Outbound) Start() error {
	return nil
}

func (o *Outbound) Close() error {
	return nil
}

type StaticPicker struct {
	closed  bool
	access  sync.Mutex
	workers []*PortalWorker
	cTask   *task.Periodic
}

func NewStaticPicker() *StaticPicker {
	p := &StaticPicker{}
	p.cTask = &task.Periodic{
		Execute:  p.cleanup,
		Interval: time.Second * 30,
	}
	p.cTask.Start()
	return p
}

func (p *StaticPicker) cleanup() error {
	p.access.Lock()
	defer p.access.Unlock()

	var activeWorkers []*PortalWorker
	for _, w := range p.workers {
		if !w.Closed() {
			activeWorkers = append(activeWorkers, w)
		} else {
			w.timer.SetTimeout(0)
		}
	}

	if len(activeWorkers) != len(p.workers) {
		p.workers = activeWorkers
	}

	return nil
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
		if w.draining {
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
	defer p.access.Unlock()

	if p.closed {
		worker.Close()
		return
	}
	p.workers = append(p.workers, worker)
}

func (p *StaticPicker) Close() {
	p.cTask.Close()
	p.access.Lock()
	defer p.access.Unlock()
	p.closed = true
	for _, worker := range p.workers {
		worker.Close()
	}
	p.workers = nil
}

type PortalWorker struct {
	client   *multiplex.ClientWorker
	control  *task.Periodic
	writer   buf.Writer
	draining bool
	counter  uint32
	timer    *signal.ActivityTimer
}

func NewPortalWorker(client *multiplex.ClientWorker) (*PortalWorker, error) {
	opt := []pipe.Option{pipe.WithSizeLimit(16 * 1024)}
	uplinkReader, uplinkWriter := pipe.New(opt...)

	ctx := context.Background()
	outbounds := []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress(internalDomain), 0),
	}}
	ctx = session.ContextWithOutbounds(ctx, outbounds)
	f := client.Dispatch(ctx, &transport.Link{
		Reader: uplinkReader,
		Writer: buf.Discard,
	}, false)
	if !f {
		return nil, errors.New("unable to dispatch control connection")
	}
	terminate := func() {
		client.Close()
	}
	w := &PortalWorker{
		client: client,
		writer: uplinkWriter,
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

	if w.draining || w.writer == nil {
		return errors.New("already disposed")
	}

	msg := &Control{}
	msg.FillInRandom()

	if w.client.TotalConnections() > 256 {
		w.draining = true
		msg.State = Control_DRAIN

		defer func() {
			common.Close(w.writer)
			w.writer = nil
		}()
	}

	w.counter = (w.counter + 1) % 5
	if w.draining || w.counter == 1 {
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
