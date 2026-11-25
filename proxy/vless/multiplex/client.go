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
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
)

// NormalizeConfig validates the pool settings and returns nil when both pools are off.
func NormalizeConfig(config *vless.Multiplex) (*vless.Multiplex, error) {
	if config.GetConcurrency() < 0 || config.GetXudpConcurrency() < 0 {
		return nil, errors.New(`multiplex "concurrency" and "xudpConcurrency" must be non-negative`)
	}
	switch config.GetXudpProxyUDP443() {
	case "", "reject", "allow", "skip":
	default:
		return nil, errors.New(`unknown "xudpProxyUDP443": `, config.GetXudpProxyUDP443())
	}
	if config.GetConcurrency() == 0 && config.GetXudpConcurrency() == 0 {
		return nil, nil
	}
	return config, nil
}

// Client owns the logical stream pools.
type Client struct {
	config *vless.Multiplex
	tcp    *Pool
	udp    *Pool
}

func NewClient(ctx context.Context, config *vless.Multiplex, network string, open func(context.Context) (context.Context, *transport.Link, error)) *Client {
	c := &Client{config: config}
	maxReuseTimes := uint32(1024)
	if network == "xdrive" {
		maxReuseTimes = 0 // unlimited
		config.Concurrency = max(config.Concurrency, 128)
		if config.XudpConcurrency > 0 {
			config.XudpConcurrency = max(config.XudpConcurrency, 128)
		}
	}
	if config.Concurrency > 0 {
		c.tcp = NewPool(ctx, ClientStrategy{MaxConcurrency: uint32(config.Concurrency), MaxConnection: maxReuseTimes}, open)
	}
	if config.XudpConcurrency > 0 {
		c.udp = NewPool(ctx, ClientStrategy{MaxConcurrency: uint32(config.XudpConcurrency), MaxConnection: maxReuseTimes}, open)
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
	if target.Network == net.Network_UDP && c.udp != nil {
		pool = c.udp
	}
	if pool == nil {
		return false, nil
	}
	if target.Network == net.Network_UDP && target.Port == 443 {
		switch c.config.GetXudpProxyUDP443() {
		case "reject", "":
			proxy.DropUDP(ctx, link.Reader)
			return true, errors.New("XUDP rejected UDP/443 traffic")
		case "skip":
			return false, nil
		}
	}
	return true, Dispatch(ctx, link, pool.Admit)
}

type deferredWriterClose struct{}

func (deferredWriterClose) Error() string          { return "defer link writer close" }
func (deferredWriterClose) DeferWriterClose() bool { return true }

// Dispatch runs a logical child. The caller owns the application endpoints.
func Dispatch(ctx context.Context, link *transport.Link, admit func(context.Context, *Session) error, finish ...func(context.Context)) error {
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
	case <-s.WaitClosed():
	}
	// The session is sealed. Only a response write already in progress can
	// still hold the application writer.
	writingResponse := s.writingResponse.Load()
	if len(finish) != 0 {
		if writingResponse {
			go finish[0](s.parent.ctx)
		} else {
			finish[0](s.parent.ctx)
		}
	} else if writingResponse {
		return deferredWriterClose{}
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
	return &Pool{ctx: ctx, strategy: strategy, open: open}
}

func (p *Pool) Admit(ctx context.Context, s *Session) error {
	p.access.Lock()
	for {
		if err := ctx.Err(); err != nil {
			p.access.Unlock()
			return err
		}
		if p.ctx.Err() != nil {
			p.access.Unlock()
			return io.ErrClosedPipe
		}
		for _, worker := range p.workers {
			if worker.TryAdmit(ctx, s) {
				p.access.Unlock()
				return nil
			}
		}
		if p.opening == nil {
			p.opening = make(chan struct{})
			break
		}
		wait := p.opening
		p.access.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ctx.Done():
			return io.ErrClosedPipe
		case <-wait:
		}
		p.access.Lock()
	}
	p.access.Unlock()
	opening, cancel := context.WithCancel(p.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	physicalCtx, physicalLink, err := p.open(opening)
	if !stopCaller() && err == nil {
		err = context.Canceled
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	p.access.Lock()
	close(p.opening)
	p.opening = nil
	var worker *ClientWorker
	if err == nil {
		worker = NewClientWorker(physicalCtx, *physicalLink, p.strategy)
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
		if physicalLink != nil {
			common.Interrupt(physicalLink.Reader)
			common.Interrupt(physicalLink.Writer)
		}
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
	c := &ClientWorker{carrier: newCarrier(ctx, stream, 16*time.Second, true), strategy: strategy}
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
	s.parent, s.ID, s.phase, s.done = m.carrier, m.count+1, outputOpen, make(chan struct{})
	return m.admitLocked(s)
}
