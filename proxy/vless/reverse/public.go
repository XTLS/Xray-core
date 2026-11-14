package reverse

import (
	"context"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/proxy/vless/multiplex"
	"github.com/xtls/xray-core/transport"
	"google.golang.org/protobuf/proto"
)

type PublicEndpoint struct {
	observer features.Feature
	tag      string
	closed   bool
	access   sync.Mutex
	workers  []*PublicWorker
}

func NewPublicEndpoint(tag string, observer features.Feature) *PublicEndpoint {
	return &PublicEndpoint{tag: tag, observer: observer}
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
	client := multiplex.NewClientWorker(ctx, *link, multiplex.ClientStrategy{})
	target := net.UDPDestination(net.DomainAddress(internalDomain), 0)
	controlCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: target}})
	s := multiplex.NewSession(controlCtx, &transport.Link{Writer: buf.Discard})
	if !client.TryAdmit(controlCtx, s) {
		client.Close()
		return errors.New("failed to admit reverse control session")
	}
	worker := &PublicWorker{
		client: client,
		timer:  signal.CancelAfterInactivity(context.Background(), func() { client.Close() }, 24*time.Hour),
	}
	defer func() {
		worker.Close()
		p.access.Lock()
		p.workers = slices.DeleteFunc(p.workers, func(current *PublicWorker) bool { return current == worker })
		p.access.Unlock()
	}()
	p.access.Lock()
	if p.closed || ctx.Err() != nil || client.Closed() {
		p.access.Unlock()
		return client.Err()
	}
	p.workers = append(p.workers, worker)
	p.access.Unlock()
	if observer, ok := p.observer.(extension.BurstObservatory); ok {
		go observer.Check([]string{p.tag})
	}
	go p.heartbeat(worker, s)
	<-client.WaitClosed()
	return client.Err()
}

func (p *PublicEndpoint) Start() error {
	return nil
}

func (p *PublicEndpoint) Close() error {
	p.access.Lock()
	p.closed = true
	workers := p.workers
	p.workers = nil
	p.access.Unlock()
	for _, worker := range workers {
		worker.Close()
	}
	return nil
}

func (p *PublicEndpoint) HandleConnection(ctx context.Context, link *transport.Link) error {
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

	return multiplex.Dispatch(ctx, link, p.Admit)
}

func (p *PublicEndpoint) Admit(ctx context.Context, s *multiplex.Session) error {
	p.access.Lock()
	defer p.access.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.closed || len(p.workers) == 0 {
		return errors.New("empty worker list")
	}

	// Failed reservations move out of this admission's candidate prefix.
	for remaining := len(p.workers); remaining > 0; {
		best, state := -1, Control_DRAIN
		var active uint32
		for i := 0; i < remaining; i++ {
			w := p.workers[i]
			a := w.client.ActiveConnections()
			if best == -1 || w.state < state || (w.state == state && a < active) {
				best, state, active = i, w.state, a
			}
		}
		if p.workers[best].client.TryAdmit(ctx, s) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining--
		p.workers[best], p.workers[remaining] = p.workers[remaining], p.workers[best]
	}

	return errors.New("no mux client worker available")
}

type PublicWorker struct {
	client *multiplex.ClientWorker
	state  Control_State // guarded by PublicEndpoint.access; zero is ACTIVE
	timer  *signal.ActivityTimer
}

func (w *PublicWorker) Close() {
	w.client.Close()
	w.timer.SetTimeout(0)
}

func (p *PublicEndpoint) heartbeat(w *PublicWorker, s *multiplex.Session) {
	var err error
	defer func() { s.CloseWithError(err) }()
	err = w.writeControl(s, Control_ACTIVE)
	if err != nil {
		w.client.Close()
		return
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	counter := uint32(1)
	for {
		select {
		case <-timer.C:
		case <-s.WaitClosed():
			err = io.ErrClosedPipe
			return
		case <-w.client.WaitClosed():
			err = io.ErrClosedPipe
			return
		}
		select {
		case <-s.WaitClosed():
			err = io.ErrClosedPipe
			return
		default:
		}
		if w.client.Closed() {
			err = io.ErrClosedPipe
			return
		}
		counter = (counter + 1) % 5
		if w.client.TotalConnections() > 256 {
			p.access.Lock()
			w.state = Control_DRAIN
			p.access.Unlock()
			err = w.writeControl(s, Control_DRAIN)
			return
		}
		if counter == 1 {
			if err = w.writeControl(s, Control_ACTIVE); err != nil {
				return
			}
		}
		timer.Reset(2 * time.Second)
	}
}

func (w *PublicWorker) writeControl(s *multiplex.Session, state Control_State) error {
	msg := &Control{State: state}
	msg.FillInRandom()
	b, err := proto.Marshal(msg)
	common.Must(err)
	w.timer.Update()
	return s.WriteMultiBuffer(buf.MergeBytes(nil, b))
}
