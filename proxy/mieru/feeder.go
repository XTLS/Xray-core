package mieru

import (
	"context"
	stderrors "errors"
	stdnet "net"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/features/routing"
)

// connFeeder is an adapter that lets the xray inbound push live connections
// into the mieru server's accept pipeline. It implements
// apicommon.StreamListenerFactory. The first time mieru calls Listen() we hand
// it our synthetic feederListener, which is then re-used for every subsequent
// Push.
type connFeeder struct {
	mu       sync.Mutex
	listener *feederListener
	ready    chan struct{}
}

func newConnFeeder() *connFeeder {
	return &connFeeder{ready: make(chan struct{})}
}

// Listen is invoked by mieru once for each configured port binding (we use
// exactly one). The returned listener will be reused for every subsequent
// Accept call.
func (f *connFeeder) Listen(_ context.Context, network, address string) (stdnet.Listener, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listener == nil {
		f.listener = newFeederListener(network, address)
		close(f.ready)
	}
	return f.listener, nil
}

// Push delivers conn to mieru's accept loop.
func (f *connFeeder) Push(ctx context.Context, conn stdnet.Conn) error {
	select {
	case <-f.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	f.mu.Lock()
	l := f.listener
	f.mu.Unlock()
	if l == nil {
		return stderrors.New("mieru feeder is not ready")
	}
	return l.Push(ctx, conn)
}

// feederListener is a net.Listener whose Accept blocks until Push is called.
type feederListener struct {
	addr  feederAddr
	conns chan stdnet.Conn

	closed    chan struct{}
	closeOnce sync.Once
}

func newFeederListener(network, address string) *feederListener {
	return &feederListener{
		addr:   feederAddr{net: network, str: address},
		conns:  make(chan stdnet.Conn, 16),
		closed: make(chan struct{}),
	}
}

func (l *feederListener) Accept() (stdnet.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, stderrors.New("mieru feeder closed")
		}
		return c, nil
	case <-l.closed:
		return nil, stderrors.New("mieru feeder closed")
	}
}

func (l *feederListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *feederListener) Addr() stdnet.Addr {
	return l.addr
}

func (l *feederListener) Push(ctx context.Context, c stdnet.Conn) error {
	select {
	case l.conns <- c:
		return nil
	case <-l.closed:
		return stderrors.New("mieru feeder closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

type feederAddr struct {
	net string
	str string
}

func (a feederAddr) Network() string { return a.net }
func (a feederAddr) String() string  { return a.str }

// trackedConn wraps a net.Conn so the inbound Process can wait until mieru
// finishes reading from it by observing Close().
type trackedConn struct {
	stdnet.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newTrackedConn(c stdnet.Conn) *trackedConn {
	return &trackedConn{Conn: c, done: make(chan struct{})}
}

func (t *trackedConn) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
	})
	return t.Conn.Close()
}

func (t *trackedConn) Done() <-chan struct{} {
	return t.done
}

// Atomic helpers ============================================================

// atomicDispatcher is a tiny wrapper around atomic.Pointer for the dispatcher
// interface so we don't have to import sync/atomic from server.go.
type atomicDispatcher struct {
	p atomic.Pointer[routing.Dispatcher]
}

func (a *atomicDispatcher) Store(d routing.Dispatcher) {
	a.p.Store(&d)
}

func (a *atomicDispatcher) Load() routing.Dispatcher {
	p := a.p.Load()
	if p == nil {
		return nil
	}
	return *p
}
