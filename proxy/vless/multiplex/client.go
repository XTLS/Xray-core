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
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

// Client owns the VLESS stream pools.
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
	return true, Dispatch(ctx, link, pool.Admit)
}

// Dispatch starts the reserved child after pool or Reverse admission releases its lock.
func Dispatch(ctx context.Context, link *transport.Link, admit func(context.Context, *Session) error) error {
	s := NewSession(ctx, link)
	if err := admit(ctx, s); err != nil {
		return err
	}
	go fetchInput(ctx, s)
	callerDone := ctx.Done()
	if session.TimeoutOnlyFromContext(ctx) {
		callerDone = nil
	}
	select {
	case <-callerDone:
		s.Close()
	case <-s.done.Wait():
	}
	return nil
}

// Pool serializes unpublished opening with cancelable admission.
type Pool struct {
	ctx      context.Context
	access   sync.Mutex
	opening  chan struct{}
	workers  []*ClientWorker
	strategy ClientStrategy
	open     func(context.Context) (context.Context, *transport.Link, error)
}

// NewPool borrows ctx; open must return a context derived from its input context.
func NewPool(ctx context.Context, strategy ClientStrategy, open func(context.Context) (context.Context, *transport.Link, error)) *Pool {
	p := &Pool{ctx: ctx, opening: make(chan struct{}, 1), strategy: strategy, open: open}
	p.opening <- struct{}{}
	return p
}

func (p *Pool) tryAdmit(ctx context.Context, s *Session) (bool, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if p.ctx.Err() != nil {
		return false, io.ErrClosedPipe
	}
	for _, worker := range p.workers {
		if worker.TryAdmit(ctx, s) {
			return true, nil
		}
	}
	return false, nil
}

func (p *Pool) Admit(ctx context.Context, s *Session) error {
	if ok, err := p.tryAdmit(ctx, s); ok || err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.ctx.Done():
		return io.ErrClosedPipe
	case <-p.opening:
	}
	defer func() { p.opening <- struct{}{} }()
	if ok, err := p.tryAdmit(ctx, s); ok || err != nil {
		return err
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
		return err
	}
	worker := NewClientWorker(physicalCtx, *physicalLink, p.strategy)
	p.access.Lock()
	err = ctx.Err()
	if !stopCaller() && err == nil {
		err = context.Canceled
	}
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	if err == nil {
		if !worker.TryAdmit(ctx, s) {
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
		return err
	}
	context.AfterFunc(worker.ctx, func() {
		cancel()
		p.access.Lock()
		p.workers = slices.DeleteFunc(p.workers, func(current *ClientWorker) bool { return current == worker })
		p.access.Unlock()
	})
	return nil
}

type ClientStrategy struct {
	MaxConcurrency uint32
	MaxConnection  uint32
}

type ClientWorker struct {
	*carrier
	strategy ClientStrategy
}

func NewClientWorker(ctx context.Context, stream transport.Link, strategy ClientStrategy) *ClientWorker {
	c := &ClientWorker{carrier: newCarrier(ctx, stream, 16*time.Second, true, 64*1024), strategy: strategy}
	go c.run(context.Background(), nil)
	return c
}

func (c *ClientWorker) TotalConnections() uint32 {
	c.RLock()
	defer c.RUnlock()
	return uint32(c.count)
}

func writeFirstPayload(s *Session) error {
	err := buf.CopyOnceTimeout(s.input, s, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return s.WriteMultiBuffer(nil)
	}
	return err
}

func fetchInput(ctx context.Context, s *Session) {
	var err error
	defer func() { s.CloseWithError(err) }()
	errors.LogInfo(ctx, "dispatching request to ", s.target)
	if err = writeFirstPayload(s); err != nil {
		errors.LogInfoInner(ctx, err, "failed to write first payload")
		return
	}
	if err = buf.Copy(s.input, s); err != nil {
		errors.LogInfoInner(ctx, err, "failed to fetch all input")
	}
}

// TryAdmit publishes this prepared child without input or foreign cleanup.
func (m *ClientWorker) TryAdmit(ctx context.Context, s *Session) bool {
	m.Lock()
	defer m.Unlock()
	if ctx.Err() != nil || m.Closed() || m.count == 65535 ||
		(m.strategy.MaxConcurrency > 0 && m.active >= int(m.strategy.MaxConcurrency)) ||
		(m.strategy.MaxConnection > 0 && uint32(m.count) >= m.strategy.MaxConnection) {
		return false
	}
	s.parent, s.ID, s.phase, s.done = m.carrier, m.count+1, outputOpen, done.New()
	return m.admitLocked(s)
}
