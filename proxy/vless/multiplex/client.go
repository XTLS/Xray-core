package multiplex

import (
	"context"
	"io"
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
	"github.com/xtls/xray-core/transport/pipe"
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
	return true, Dispatch(ctx, link, true, pool.PickAvailable)
}

// Dispatch shares child admission between native pools and Reverse static picks.
func Dispatch(ctx context.Context, link *transport.Link, wait bool, pick func(context.Context) (*ClientWorker, error)) error {
	for attempt := 0; attempt < 16; attempt++ {
		worker, err := pick(ctx)
		if err != nil {
			return err
		}
		if worker.Dispatch(ctx, link, wait) {
			return nil
		}
	}
	return errors.New("unable to find an available multiplex client")
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

func (p *Pool) available() *ClientWorker {
	p.access.Lock()
	defer p.access.Unlock()
	for _, worker := range p.workers {
		if !worker.IsFull() {
			return worker
		}
	}
	return nil
}

func (p *Pool) PickAvailable(ctx context.Context) (*ClientWorker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	if worker := p.available(); worker != nil {
		return worker, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.ctx.Done():
		return nil, io.ErrClosedPipe
	case <-p.opening:
	}
	defer func() { p.opening <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.ctx.Err() != nil {
		return nil, io.ErrClosedPipe
	}
	if worker := p.available(); worker != nil {
		return worker, nil
	}
	opening, cancel := context.WithCancel(p.ctx)
	stopCaller := context.AfterFunc(ctx, cancel)
	opening = session.ContextWithOutbounds(opening, []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("v1.mux.cool"), 9527),
	}})
	physicalCtx, link, err := p.open(opening)
	detached := stopCaller()
	if !detached && err == nil {
		err = context.Canceled
	}
	if err == nil {
		err = ctx.Err()
	}
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	if err != nil {
		cancel()
		if link != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
		return nil, err
	}
	worker := NewClientWorker(*link, p.strategy)
	p.access.Lock()
	err = ctx.Err()
	if p.ctx.Err() != nil {
		err = io.ErrClosedPipe
	}
	if err == nil {
		p.workers = append(p.workers, worker)
	}
	p.access.Unlock()
	if err != nil {
		cancel()
		worker.Close()
		return nil, err
	}
	context.AfterFunc(physicalCtx, func() {
		cancel()
		worker.Close()
		p.access.Lock()
		defer p.access.Unlock()
		for i, current := range p.workers {
			if current == worker {
				copy(p.workers[i:], p.workers[i+1:])
				p.workers[len(p.workers)-1] = nil
				p.workers = p.workers[:len(p.workers)-1]
				break
			}
		}
	})
	return worker, nil
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
	c := &ClientWorker{carrier: newCarrier(stream, 16*time.Second), strategy: strategy}
	go c.run(context.Background(), nil)
	return c
}

func (c *ClientWorker) TotalConnections() uint32 { return uint32(c.sessionManager.Count()) }

func writeFirstPayload(reader buf.Reader, writer *Writer) error {
	err := buf.CopyOnceTimeout(reader, writer, time.Millisecond*100)
	if err == buf.ErrNotTimeoutReader || err == buf.ErrReadTimeout {
		return writer.WriteMultiBuffer(buf.MultiBuffer{})
	}

	if err != nil {
		return err
	}

	return nil
}

func fetchInput(ctx context.Context, s *Session, output buf.Writer) {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	var inbound *session.Inbound
	if session.IsReverseMuxFromContext(ctx) {
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

func (m *ClientWorker) IsClosing() bool {
	sm := m.sessionManager
	if m.strategy.MaxConnection > 0 && sm.Count() >= int(m.strategy.MaxConnection) {
		return true
	}
	return false
}

// IsFull returns true if this ClientWorker is unable to accept more connections.
// it might be because it is closing, or the number of connections has reached the limit.
func (m *ClientWorker) IsFull() bool {
	if m.IsClosing() || m.Closed() {
		return true
	}

	sm := m.sessionManager
	if m.strategy.MaxConcurrency > 0 && sm.Size() >= int(m.strategy.MaxConcurrency) {
		return true
	}
	return false
}

func (m *ClientWorker) Dispatch(ctx context.Context, link *transport.Link, wait bool) bool {
	if ctx.Err() != nil || m.IsFull() {
		return false
	}
	transferType := protocol.TransferTypeStream
	outbounds := session.OutboundsFromContext(ctx)
	if outbounds[len(outbounds)-1].Target.Network == net.Network_UDP {
		transferType = protocol.TransferTypePacket
	}
	s := m.sessionManager.Allocate(&m.strategy, link.Reader, link.Writer, transferType)
	if s == nil {
		return false
	}
	go fetchInput(ctx, s, m.link.Writer)
	_, pipeReader := link.Reader.(*pipe.Reader)
	if wait || !pipeReader {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.done.Wait():
		}
	}
	return true
}
