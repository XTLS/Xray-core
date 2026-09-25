package splithttp

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
)

// coalescingHTTP2Pool restores the per-address in-flight dial coalescing that
// x/net/http2 used before Go 1.27. It still creates additional connections when
// every established connection has reached the peer's concurrent stream limit.
type coalescingHTTP2Pool struct {
	access sync.Mutex

	transport *http2.Transport
	dial      func(context.Context) (net.Conn, error)
	conns     map[string][]*http2.ClientConn
	dialing   map[string]*http2DialCall
}

type http2DialCall struct {
	ctx  context.Context
	done chan struct{}
	err  error
}

func newHTTP2Transport(
	dial func(context.Context) (net.Conn, error),
	idleTimeout time.Duration,
	readIdleTimeout time.Duration,
) *http2.Transport {
	transport := &http2.Transport{
		IdleConnTimeout: idleTimeout,
		ReadIdleTimeout: readIdleTimeout,
	}
	transport.ConnPool = &coalescingHTTP2Pool{
		transport: transport,
		dial:      dial,
		conns:     make(map[string][]*http2.ClientConn),
		dialing:   make(map[string]*http2DialCall),
	}
	return transport
}

func (p *coalescingHTTP2Pool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	for {
		p.access.Lock()
		conns := p.conns[addr]
		active := conns[:0]
		var available *http2.ClientConn
		for _, conn := range conns {
			if conn.State().Closed {
				continue
			}
			active = append(active, conn)
			if available == nil && conn.ReserveNewRequest() {
				available = conn
			}
		}
		p.conns[addr] = active
		if available != nil {
			p.access.Unlock()
			return available, nil
		}

		call := p.dialing[addr]
		if call == nil {
			call = &http2DialCall{
				ctx:  req.Context(),
				done: make(chan struct{}),
			}
			p.dialing[addr] = call
			go p.dialConn(addr, call)
		}
		p.access.Unlock()

		select {
		case <-call.done:
			if call.err == nil {
				continue
			}
			// If the request that initiated the shared dial was canceled,
			// another live request may retry with its own context.
			if call.ctx != req.Context() &&
				(errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) &&
				call.ctx.Err() != nil {
				continue
			}
			return nil, call.err
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
}

func (p *coalescingHTTP2Pool) dialConn(addr string, call *http2DialCall) {
	rawConn, err := p.dial(call.ctx)
	var clientConn *http2.ClientConn
	if err == nil {
		clientConn, err = p.transport.NewClientConn(rawConn)
		if err != nil {
			_ = rawConn.Close()
		}
	}

	p.access.Lock()
	delete(p.dialing, addr)
	if err == nil {
		p.conns[addr] = append(p.conns[addr], clientConn)
	}
	call.err = err
	p.access.Unlock()
	close(call.done)
}

func (p *coalescingHTTP2Pool) MarkDead(dead *http2.ClientConn) {
	p.access.Lock()
	defer p.access.Unlock()
	for addr, conns := range p.conns {
		active := conns[:0]
		for _, conn := range conns {
			if conn != dead {
				active = append(active, conn)
			}
		}
		if len(active) == 0 {
			delete(p.conns, addr)
		} else {
			p.conns[addr] = active
		}
	}
}

var _ http2.ClientConnPool = (*coalescingHTTP2Pool)(nil)
