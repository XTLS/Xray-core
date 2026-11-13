package multiplex

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
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

// Client owns the VLESS stream pools. A nil configuration disables multiplexing.
type Client struct {
	config *vless.Multiplex
	tcp    *Pool
	udp    *Pool
}

func NewClient(ctx context.Context, config *vless.Multiplex, network string, open func(context.Context) (context.Context, *transport.Link, error)) *Client {
	c := &Client{config: config}
	pool := func(concurrency int32) *Pool {
		return NewPool(ctx, ClientStrategy{MaxConcurrency: uint32(concurrency), MaxConnection: 1024}, open)
	}
	concurrency := config.Concurrency
	if concurrency == 0 {
		concurrency = 8
	}
	if concurrency > 0 {
		if network == "xdrive" {
			concurrency = max(concurrency, 128)
		}
		c.tcp = pool(concurrency)
	}
	if config.XudpConcurrency > 0 {
		c.udp = pool(config.XudpConcurrency)
	}
	return c
}

func (c *Client) Close() {
	if c.tcp != nil {
		c.tcp.Close()
	}
	if c.udp != nil {
		c.udp.Close()
	}
}

func (c *Client) Dispatch(ctx context.Context, link *transport.Link) (bool, error) {
	if c == nil {
		return false, nil
	}
	pool := c.tcp
	outbounds := session.OutboundsFromContext(ctx)
	target := outbounds[len(outbounds)-1].Target
	if target.Network == net.Network_UDP {
		if target.Port == 443 {
			switch c.config.XudpProxyUDP443 {
			case "reject", "":
				return true, errors.New("XUDP rejected UDP/443 traffic")
			case "skip":
				return false, nil
			}
		}
		if c.config.XudpConcurrency < 0 {
			return false, nil
		}
		if c.udp != nil {
			pool = c.udp
		}
	}
	if pool == nil {
		return false, nil
	}
	return true, Dispatch(ctx, link, true, pool.Admit)
}

// Dispatch starts the reserved child after pool or Reverse admission releases its lock.
func Dispatch(ctx context.Context, link *transport.Link, wait bool, admit func(context.Context, *transport.Link) (*Session, error)) error {
	s, err := admit(ctx, link)
	if err != nil {
		return err
	}
	go fetchInput(ctx, s, s.sender)
	if wait {
		callerDone := ctx.Done()
		if session.TimeoutOnlyFromContext(ctx) {
			callerDone = nil
		}
		select {
		case <-callerDone:
			s.Close()
		case <-s.done.Wait():
		}
	}
	return nil
}

// Pool serializes unpublished opening with cancelable admission.
type Pool struct {
	ctx      context.Context
	cancel   context.CancelFunc
	access   sync.Mutex
	opening  chan struct{}
	workers  []*ClientWorker
	strategy ClientStrategy
	open     func(context.Context) (context.Context, *transport.Link, error)
}

// NewPool requires open to return a context derived from its input context.
func NewPool(ctx context.Context, strategy ClientStrategy, open func(context.Context) (context.Context, *transport.Link, error)) *Pool {
	ctx, cancel := context.WithCancel(ctx)
	p := &Pool{ctx: ctx, cancel: cancel, opening: make(chan struct{}, 1), strategy: strategy, open: open}
	p.opening <- struct{}{}
	return p
}

func (p *Pool) Close() error {
	p.cancel()
	return nil
}

func (p *Pool) tryAdmit(ctx context.Context, link *transport.Link) (*Session, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	for _, worker := range p.workers {
		if s := worker.TryAdmit(ctx, link); s != nil {
			return s, nil
		}
	}
	return nil, nil
}

func (p *Pool) Admit(ctx context.Context, link *transport.Link) (*Session, error) {
	if s, err := p.tryAdmit(ctx, link); s != nil || err != nil {
		return s, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.ctx.Done():
		return nil, io.ErrClosedPipe
	case <-p.opening:
	}
	defer func() { p.opening <- struct{}{} }()
	if s, err := p.tryAdmit(ctx, link); s != nil || err != nil {
		return s, err
	}
	opening, cancel := context.WithCancel(p.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	physicalCtx, physicalLink, err := p.open(opening)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	if err != nil {
		stopCaller()
		cancel()
		if physicalLink != nil {
			common.Interrupt(physicalLink.Reader)
			common.Interrupt(physicalLink.Writer)
		}
		return nil, err
	}
	worker := NewClientWorker(*physicalLink, p.strategy)
	p.access.Lock()
	err = ctx.Err()
	if !stopCaller() && err == nil {
		err = context.Canceled
	}
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	var s *Session
	if err == nil {
		s = worker.TryAdmit(ctx, link)
		if s == nil {
			err = ctx.Err()
			if err == nil {
				err = errors.New("unable to admit multiplex child")
			}
		} else {
			p.workers = append(p.workers, worker)
		}
	}
	p.access.Unlock()
	if err != nil {
		cancel()
		worker.Close()
		return nil, err
	}
	stopPhysical := context.AfterFunc(physicalCtx, func() { worker.Close() })
	context.AfterFunc(worker.ctx, func() {
		stopPhysical()
		cancel()
		p.access.Lock()
		p.workers = slices.DeleteFunc(p.workers, func(current *ClientWorker) bool { return current == worker })
		p.access.Unlock()
	})
	return s, nil
}

type ClientStrategy struct {
	MaxConcurrency uint32
	MaxConnection  uint32
}

type ClientWorker struct {
	*carrier
	strategy ClientStrategy
}

func NewClientWorker(stream transport.Link, strategy ClientStrategy) *ClientWorker {
	c := &ClientWorker{carrier: newCarrier(stream, 16*time.Second, true), strategy: strategy}
	go c.run(context.Background(), nil)
	return c
}

func (c *ClientWorker) TotalConnections() uint32 { return uint32(c.sessionManager.Count()) }

func writeFirstPayload(reader buf.Reader, writer *Writer) error {
	err := buf.CopyOnceTimeout(reader, writer, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return writer.WriteMultiBuffer(buf.MultiBuffer{})
	}

	return err
}

func fetchInput(ctx context.Context, s *Session, output buf.Writer) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	var inbound *session.Inbound
	if session.IsReverseMultiplexFromContext(ctx) {
		inbound = session.InboundFromContext(ctx)
	}
	writer := NewWriter(s.ID, ob.Target, output, s.transferType, xudp.GetGlobalID(ctx), inbound)
	defer s.Close()
	defer writer.Close()

	errors.LogInfo(ctx, "dispatching request to ", ob.Target)
	if err := writeFirstPayload(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to write first payload")
		writer.hasError = true
		return
	}

	if err := buf.Copy(s.input, writer); err != nil {
		errors.LogInfoInner(ctx, err, "failed to fetch all input")
		writer.hasError = true
		return
	}
}

// TryAdmit reserves a child without starting input or invoking foreign cleanup.
func (m *ClientWorker) TryAdmit(ctx context.Context, link *transport.Link) *Session {
	m.sessionManager.Lock()
	defer m.sessionManager.Unlock()
	if ctx.Err() != nil || m.Closed() {
		return nil
	}
	transferType := protocol.TransferTypeStream
	outbounds := session.OutboundsFromContext(ctx)
	if outbounds[len(outbounds)-1].Target.Network == net.Network_UDP {
		transferType = protocol.TransferTypePacket
	}
	s := m.sessionManager.allocate(&m.strategy, link.Reader, link.Writer, transferType)
	if s != nil {
		s.sender = m.carrier
	}
	return s
}
