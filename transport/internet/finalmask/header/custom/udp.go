package custom

import (
	"bytes"
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const udpStandaloneBufferSize = 4096

type udpCustomClient struct {
	client []*UDPItem
	server []*UDPItem
	merged []byte
	read   int
	state  *stateStore
	// mu guards vars: Match() writes it from the ReadFrom fan-in loop while
	// WriteTo (called concurrently by many client sessions sharing this one
	// outbound PacketConn) reads it as a fallback when no per-addr state
	// exists yet - the adjacent stateStore already has its own lock for
	// exactly this reason, but this plain field didn't.
	mu   sync.Mutex
	vars map[string][]byte
}

// currentVars returns a defensive copy of the last-matched vars, safe to
// call concurrently with Match().
func (h *udpCustomClient) currentVars() map[string][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return cloneVars(h.vars)
}

func (h *udpCustomClient) Serialize(b []byte) {
	evaluated, err := evaluateUDPItems(h.client)
	if err != nil || len(evaluated) != len(h.merged) {
		copy(b, h.merged)
		return
	}
	copy(b, evaluated)
}

func (h *udpCustomClient) Match(b []byte, addr net.Addr) bool {
	var initial map[string][]byte
	if h.state != nil {
		initial, _ = h.state.get(udpStateKey(addr))
	}
	vars, ok := matchUDPItems(h.server, b, h.read, initial)
	if ok {
		h.mu.Lock()
		h.vars = vars
		h.mu.Unlock()
		if h.state != nil {
			h.state.set(udpStateKey(addr), vars)
		}
	}
	return ok
}

type udpCustomClientConn struct {
	net.PacketConn
	header *udpCustomClient
}

func NewConnClientUDP(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
	conn := &udpCustomClientConn{
		PacketConn: raw,
		header: &udpCustomClient{
			client: c.Client,
			server: c.Server,
			state:  newStateStore(5 * time.Second),
			vars:   make(map[string][]byte),
		},
	}
	clientSavedSizes := collectSavedUDPSizes(conn.header.client)
	size, err := measureUDPItems(conn.header.client)
	if err != nil {
		return nil, err
	}
	conn.header.merged = make([]byte, size)
	conn.header.read, err = measureUDPItemsWithFallback(conn.header.server, clientSavedSizes)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *udpCustomClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b := p
	if len(b) < finalmask.UDPSize {
		buf := buf.New()
		buf.Resize(0, finalmask.UDPSize)
		b = buf.Bytes()
		defer buf.Release()
	}

	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}

		if !c.header.Match(b[:n], addr) {
			errors.LogError(context.Background(), "[mask] drop packet from ", addr, " with size ", n, " > header mismatch")
			continue
		}

		copy(p, b[c.header.read:n])
		return n - c.header.read, addr, nil
	}
}

func (c *udpCustomClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := buf.New()
	buf.Resize(0, finalmask.UDPSize)
	b := buf.Bytes()
	defer buf.Release()

	ctx := newEvalContextWithAddrs(c.PacketConn.LocalAddr(), addr)
	if vars, ok := c.header.state.get(udpStateKey(addr)); ok {
		ctx.vars = cloneVars(vars)
	} else if v := c.header.currentVars(); len(v) > 0 {
		ctx.vars = v
	}
	evaluated, err := evaluateUDPItemsWithContext(c.header.client, ctx)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}
	if len(evaluated) != len(c.header.merged) {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p), " > header size mismatch")
		return 0, nil
	}
	c.header.state.set(udpStateKey(addr), ctx.vars)
	copy(b, evaluated)
	copy(b[len(evaluated):], p)
	_, err = c.PacketConn.WriteTo(b[:len(evaluated)+len(p)], addr)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, err
	}

	return len(p), nil
}

type udpCustomServer struct {
	client []*UDPItem
	server []*UDPItem
	merged []byte
	read   int
	state  *stateStore
	// mu guards vars - see the matching comment on udpCustomClient.mu.
	mu   sync.Mutex
	vars map[string][]byte
}

// currentVars returns a defensive copy of the last-matched vars, safe to
// call concurrently with Match().
func (h *udpCustomServer) currentVars() map[string][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return cloneVars(h.vars)
}

func (h *udpCustomServer) Serialize(b []byte) {
	evaluated, err := evaluateUDPItems(h.server)
	if err != nil || len(evaluated) != len(h.merged) {
		copy(b, h.merged)
		return
	}
	copy(b, evaluated)
}

func (h *udpCustomServer) Match(b []byte, addr net.Addr) bool {
	var initial map[string][]byte
	if h.state != nil {
		initial, _ = h.state.get(udpStateKey(addr))
	}
	vars, ok := matchUDPItems(h.client, b, h.read, initial)
	if ok {
		h.mu.Lock()
		h.vars = vars
		h.mu.Unlock()
		if h.state != nil {
			h.state.set(udpStateKey(addr), vars)
		}
	}
	return ok
}

type udpCustomServerConn struct {
	net.PacketConn
	header *udpCustomServer
}

func NewConnServerUDP(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
	conn := &udpCustomServerConn{
		PacketConn: raw,
		header: &udpCustomServer{
			client: c.Client,
			server: c.Server,
			state:  newStateStore(5 * time.Second),
			vars:   make(map[string][]byte),
		},
	}
	clientSavedSizes := collectSavedUDPSizes(conn.header.client)
	size, err := measureUDPItemsWithFallback(conn.header.server, clientSavedSizes)
	if err != nil {
		return nil, err
	}
	conn.header.merged = make([]byte, size)
	conn.header.read, err = measureUDPItems(conn.header.client)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *udpCustomServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b := p
	if len(b) < finalmask.UDPSize {
		buf := buf.New()
		buf.Resize(0, finalmask.UDPSize)
		b = buf.Bytes()
		defer buf.Release()
	}

	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}

		if !c.header.Match(b[:n], addr) {
			errors.LogError(context.Background(), "[mask] drop packet from ", addr, " with size ", n, " > header mismatch")
			continue
		}

		copy(p, b[c.header.read:n])
		return n - c.header.read, addr, nil
	}
}

func (c *udpCustomServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := buf.New()
	buf.Resize(0, finalmask.UDPSize)
	b := buf.Bytes()
	defer buf.Release()

	ctx := newEvalContextWithAddrs(c.PacketConn.LocalAddr(), addr)
	if vars, ok := c.header.state.get(udpStateKey(addr)); ok {
		ctx.vars = cloneVars(vars)
	} else if v := c.header.currentVars(); len(v) > 0 {
		ctx.vars = v
	}
	evaluated, err := evaluateUDPItemsWithContext(c.header.server, ctx)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}
	if len(evaluated) != len(c.header.merged) {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p), " > header size mismatch")
		return 0, nil
	}
	c.header.state.set(udpStateKey(addr), ctx.vars)
	copy(b, evaluated)
	copy(b[len(evaluated):], p)
	_, err = c.PacketConn.WriteTo(b[:len(evaluated)+len(p)], addr)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, err
	}

	return len(p), nil
}

func matchUDPItems(items []*UDPItem, data []byte, totalSize int, initial map[string][]byte) (map[string][]byte, bool) {
	if len(data) < totalSize {
		return nil, false
	}

	ctx := newEvalContext()
	ctx.vars = cloneVars(initial)
	offset := 0
	for _, item := range items {
		length, err := measureItem(item.Rand, item.Packet, item.Save, item.Var, item.Expr, sizeMapFromEvalContext(ctx))
		if err != nil {
			return nil, false
		}
		if len(data[offset:]) < length {
			return nil, false
		}
		segment := append([]byte(nil), data[offset:offset+length]...)
		switch {
		case item.Rand > 0:
		case len(item.Packet) > 0:
			if !bytes.Equal(item.Packet, segment) {
				return nil, false
			}
		case item.Var != "":
			saved, ok := ctx.vars[item.Var]
			if !ok || !bytes.Equal(saved, segment) {
				return nil, false
			}
		case item.Expr != nil:
			evaluated, err := evaluateExpr(item.Expr, ctx)
			if err != nil {
				return nil, false
			}
			expected, err := evaluated.asBytes()
			if err != nil || !bytes.Equal(expected, segment) {
				return nil, false
			}
		}
		if item.Save != "" {
			ctx.vars[item.Save] = segment
		}
		offset += length
	}

	return ctx.vars, true
}

func udpStateKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

type udpCustomStandaloneClientConn struct {
	net.PacketConn
	client []*UDPItem
	server []*UDPItem
	state  *stateStore
	read   int
	mu     sync.Mutex
	once   sync.Once
	queue  chan udpStandalonePacket
	wait   map[string]*udpStandaloneWaiter
}

type udpStandalonePacket struct {
	data []byte
	addr net.Addr
	err  error
}

type udpStandaloneWaiter struct {
	vars map[string][]byte
	// done is closed (never sent-on) so every concurrent WriteTo call
	// waiting on the same in-flight handshake wakes up - a single buffered
	// `chan error` only delivers to one of N waiters. err is set before
	// close(done) and must only be read after <-done returns (closing a
	// channel happens-before a receive that completes because of the
	// close, per the Go memory model, so this needs no extra lock).
	done chan struct{}
	err  error
}

func NewConnClientUDPStandalone(c *UDPStandaloneConfig, raw net.PacketConn) (net.PacketConn, error) {
	clientSavedSizes := collectSavedUDPSizes(c.Client)
	read, err := measureUDPItemsWithFallback(c.Server, clientSavedSizes)
	if err != nil {
		return nil, err
	}

	return &udpCustomStandaloneClientConn{
		PacketConn: raw,
		client:     c.Client,
		server:     c.Server,
		state:      newStateStore(5 * time.Second),
		read:       read,
		queue:      make(chan udpStandalonePacket, 16),
		wait:       make(map[string]*udpStandaloneWaiter),
	}, nil
}

func (c *udpCustomStandaloneClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.ensureReader()
	packet, ok := <-c.queue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if packet.err != nil {
		return 0, packet.addr, packet.err
	}
	if len(packet.data) > len(p) {
		copy(p, packet.data[:len(p)])
		return len(p), packet.addr, nil
	}
	copy(p, packet.data)
	return len(packet.data), packet.addr, nil
}

func (c *udpCustomStandaloneClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.ensureReader()
	key := udpStateKey(addr)
	if _, ok := c.state.get(key); !ok {
		var localAddr net.Addr
		if c.PacketConn != nil {
			localAddr = c.PacketConn.LocalAddr()
		}

		ctx := newEvalContextWithAddrs(localAddr, addr)
		request, err := evaluateUDPItemsWithContext(c.client, ctx)
		if err != nil {
			return 0, err
		}
		waiter, isNew := c.registerOrJoinWaiter(key, ctx.vars)
		if isNew {
			if _, err := c.PacketConn.WriteTo(request, addr); err != nil {
				c.unregisterWaiter(key, waiter)
				waiter.err = err
				close(waiter.done)
				return 0, err
			}
		}
		<-waiter.done
		if waiter.err != nil {
			return 0, waiter.err
		}
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *udpCustomStandaloneClientConn) ensureReader() {
	c.once.Do(func() {
		go c.readerLoop(c.queue)
	})
}

// registerOrJoinWaiter returns the already in-flight waiter for key if one
// exists (isNew=false - the caller must NOT resend the handshake request,
// just wait for the existing one to complete), or creates and registers a
// new one (isNew=true). Used to overwrite any existing entry unconditionally,
// so two concurrent first-packet WriteTo calls to the same not-yet-
// established addr silently orphaned the first caller's waiter, which then
// blocked forever on <-waiter.done - even connection teardown never woke it,
// since failWaiters only drains whatever is *currently* in c.wait.
func (c *udpCustomStandaloneClientConn) registerOrJoinWaiter(key string, vars map[string][]byte) (waiter *udpStandaloneWaiter, isNew bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.wait[key]; ok {
		return existing, false
	}
	waiter = &udpStandaloneWaiter{
		vars: cloneVars(vars),
		done: make(chan struct{}),
	}
	c.wait[key] = waiter
	return waiter, true
}

func (c *udpCustomStandaloneClientConn) unregisterWaiter(key string, waiter *udpStandaloneWaiter) {
	c.mu.Lock()
	if c.wait[key] == waiter {
		delete(c.wait, key)
	}
	c.mu.Unlock()
}

func (c *udpCustomStandaloneClientConn) readerLoop(queue chan udpStandalonePacket) {
	buf := make([]byte, udpStandaloneBufferSize)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			c.failWaiters(err)
			queue <- udpStandalonePacket{addr: addr, err: err}
			close(queue)
			return
		}
		data := append([]byte(nil), buf[:n]...)
		if c.tryCompleteHandshake(addr, data) {
			continue
		}
		queue <- udpStandalonePacket{data: data, addr: addr}
	}
}

func (c *udpCustomStandaloneClientConn) tryCompleteHandshake(addr net.Addr, data []byte) bool {
	key := udpStateKey(addr)
	c.mu.Lock()
	waiter, ok := c.wait[key]
	c.mu.Unlock()
	if !ok || len(data) != c.read {
		return false
	}

	vars, matched := matchUDPItems(c.server, data, c.read, waiter.vars)
	if !matched {
		return false
	}

	c.state.set(key, vars)
	c.mu.Lock()
	if c.wait[key] == waiter {
		delete(c.wait, key)
	}
	c.mu.Unlock()
	close(waiter.done)
	return true
}

func (c *udpCustomStandaloneClientConn) failWaiters(err error) {
	c.mu.Lock()
	waiters := c.wait
	c.wait = make(map[string]*udpStandaloneWaiter)
	c.mu.Unlock()
	for _, waiter := range waiters {
		waiter.err = err
		close(waiter.done)
	}
}

type udpCustomStandaloneServerConn struct {
	net.PacketConn
	client []*UDPItem
	server []*UDPItem
	state  *stateStore
	read   int
}

func NewConnServerUDPStandalone(c *UDPStandaloneConfig, raw net.PacketConn) (net.PacketConn, error) {
	read, err := measureUDPItems(c.Client)
	if err != nil {
		return nil, err
	}

	return &udpCustomStandaloneServerConn{
		PacketConn: raw,
		client:     c.Client,
		server:     c.Server,
		state:      newStateStore(5 * time.Second),
		read:       read,
	}, nil
}

func (c *udpCustomStandaloneServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := p
	copyBack := false
	if len(buf) < udpStandaloneBufferSize {
		buf = make([]byte, udpStandaloneBufferSize)
		copyBack = true
	}

	for {
		n, addr, err = c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n == c.read {
			vars, ok := matchUDPItems(c.client, buf[:n], c.read, nil)
			if ok {
				var localAddr net.Addr
				if c.PacketConn != nil {
					localAddr = c.PacketConn.LocalAddr()
				}
				ctx := newEvalContextWithAddrs(localAddr, addr)
				ctx.vars = cloneVars(vars)
				response, err := evaluateUDPItemsWithContext(c.server, ctx)
				if err != nil {
					return 0, addr, err
				}
				if _, err := c.PacketConn.WriteTo(response, addr); err != nil {
					return 0, addr, err
				}
				c.state.set(udpStateKey(addr), ctx.vars)
				continue
			}
		}

		if copyBack {
			copy(p, buf[:n])
		}
		return n, addr, nil
	}
}

func (c *udpCustomStandaloneServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.PacketConn.WriteTo(p, addr)
}
