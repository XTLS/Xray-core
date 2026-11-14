package reverse

import (
	"context"
	"io"
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
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

type PublicEndpoint struct {
	observer features.Feature
	tag      string
	picker   *StaticPicker
}

func NewPublicEndpoint(tag string, observer features.Feature) *PublicEndpoint {
	picker := NewStaticPicker()
	return &PublicEndpoint{tag: tag, observer: observer, picker: picker}
}

func (p *PublicEndpoint) Tag() string                          { return p.tag }
func (p *PublicEndpoint) SenderSettings() *serial.TypedMessage { return nil }
func (p *PublicEndpoint) ProxySettings() *serial.TypedMessage  { return nil }
func (p *PublicEndpoint) Dispatch(ctx context.Context, link *transport.Link) {
	if err := p.HandleConnection(ctx, link); err != nil {
		errors.LogInfoInner(ctx, err, "failed to process reverse connection")
		common.Interrupt(link.Writer)
		common.Interrupt(link.Reader)
	}
}

func (p *PublicEndpoint) Accept(ctx context.Context, link *transport.Link) error {
	client := multiplex.NewClientWorker(*link, multiplex.ClientStrategy{})
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	worker, err := NewPublicWorker(client)
	if err != nil {
		client.Close()
		return errors.New("failed to create public worker").Base(err)
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

func (p *PublicEndpoint) Start() error {
	return nil
}

func (p *PublicEndpoint) Close() error {
	p.picker.Close()
	return nil
}

func (p *PublicEndpoint) HandleConnection(ctx context.Context, link *transport.Link) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if ob == nil {
		return errors.New("outbound metadata not found")
	}

	ctx = session.ContextWithIsReverseMultiplex(ctx, true)

	if ob.Target.Network == net.Network_UDP && ob.OriginalTarget.Address != nil && ob.OriginalTarget.Address != ob.Target.Address {
		link.Reader = &buf.EndpointOverrideReader{Reader: link.Reader, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
		link.Writer = &buf.EndpointOverrideWriter{Writer: link.Writer, Dest: ob.Target.Address, OriginalDest: ob.OriginalTarget.Address}
	}

	return multiplex.Dispatch(ctx, link, true, p.picker.Admit)
}

type StaticPicker struct {
	closed  bool
	access  sync.Mutex
	workers []*PublicWorker
}

func NewStaticPicker() *StaticPicker {
	return &StaticPicker{}
}

func (p *StaticPicker) Admit(ctx context.Context, link *transport.Link) (*multiplex.Session, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.closed || len(p.workers) == 0 {
		return nil, errors.New("empty worker list")
	}

	// Failed reservations move out of this admission's candidate prefix.
	for remaining := len(p.workers); remaining > 0; {
		best := 0
		draining, active := p.workers[0].draining.Load(), p.workers[0].client.ActiveConnections()
		for i := 1; i < remaining; i++ {
			w := p.workers[i]
			d, a := w.draining.Load(), w.client.ActiveConnections()
			if (draining && !d) || (draining == d && a < active) {
				best, draining, active = i, d, a
			}
		}
		if s := p.workers[best].client.TryAdmit(ctx, link); s != nil {
			return s, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		remaining--
		p.workers[best], p.workers[remaining] = p.workers[remaining], p.workers[best]
	}

	return nil, errors.New("no multiplex client worker available")
}

func (p *StaticPicker) AddWorker(worker *PublicWorker) {
	p.access.Lock()
	if p.closed {
		p.access.Unlock()
		worker.Close()
		return
	}
	p.workers = append(p.workers, worker)
	p.access.Unlock()
}

func (p *StaticPicker) RemoveWorker(worker *PublicWorker) {
	p.access.Lock()
	defer p.access.Unlock()
	p.workers = slices.DeleteFunc(p.workers, func(current *PublicWorker) bool { return current == worker })
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

type PublicWorker struct {
	client   *multiplex.ClientWorker
	draining atomic.Bool
	timer    *signal.ActivityTimer
}

func NewPublicWorker(client *multiplex.ClientWorker) (*PublicWorker, error) {
	w := &PublicWorker{
		client: client,
		timer:  signal.CancelAfterInactivity(context.Background(), func() { client.Close() }, 24*time.Hour),
	}
	r := &controlReader{worker: w, ready: done.New(), stopped: done.New(), first: true}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.UDPDestination(net.DomainAddress(internalDomain), 0),
	}})
	err := multiplex.Dispatch(ctx, &transport.Link{Reader: r, Writer: buf.Discard}, false, func(ctx context.Context, link *transport.Link) (*multiplex.Session, error) {
		if s := client.TryAdmit(ctx, link); s != nil {
			return s, nil
		}
		return nil, errors.New("failed to admit reverse control session")
	})
	if err != nil {
		w.Close()
		return nil, err
	}
	select {
	case <-r.ready.Wait():
	case <-r.stopped.Wait():
	case <-client.WaitClosed():
	}
	select {
	case <-r.ready.Wait():
		if !client.Closed() {
			return w, nil
		}
	default:
	}
	w.Close()
	return nil, errors.New("failed to initialize reverse control session")
}

func (w *PublicWorker) Close() {
	w.client.Close()
	w.timer.SetTimeout(0)
}

type controlReader struct {
	worker  *PublicWorker
	ready   *done.Instance
	stopped *done.Instance
	first   bool
	counter uint32
}

func (r *controlReader) Interrupt() { r.stopped.Close() }

func (r *controlReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

func (r *controlReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if !r.first {
		// fetchInput enters here only after the preceding encoded write returns.
		r.ready.Close()
	}
	for {
		if r.stopped.Done() || r.worker.Closed() {
			return nil, io.ErrClosedPipe
		}
		if r.worker.draining.Load() {
			return nil, io.EOF
		}
		if !r.first {
			timer := time.NewTimer(2 * time.Second)
			select {
			case <-timer.C:
			case <-r.stopped.Wait():
				timer.Stop()
				return nil, io.ErrClosedPipe
			case <-r.worker.client.WaitClosed():
				timer.Stop()
				return nil, io.ErrClosedPipe
			}
		}
		if r.stopped.Done() || r.worker.Closed() {
			return nil, io.ErrClosedPipe
		}
		r.first = false
		msg := &Control{}
		msg.FillInRandom()
		if r.worker.client.TotalConnections() > 256 {
			r.worker.draining.Store(true)
			msg.State = Control_DRAIN
		}

		r.counter = (r.counter + 1) % 5
		if r.worker.draining.Load() || r.counter == 1 {
			b, err := proto.Marshal(msg)
			common.Must(err)
			r.worker.timer.Update()
			return buf.MergeBytes(nil, b), nil
		}
	}
}

func (w *PublicWorker) Closed() bool {
	return w.client.Closed()
}
