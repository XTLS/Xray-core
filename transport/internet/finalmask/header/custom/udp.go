package custom

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

const udpStandaloneBufferSize = 4096

type udpCustomClient struct {
	client []*UDPItem
	server []*UDPItem
	merged []byte
	read   int
	addr   net.Addr
	state  *stateStore
	vars   map[string][]byte
}

func (h *udpCustomClient) Serialize(b []byte) {
	evaluated, err := evaluateUDPItems(h.client)
	if err != nil || len(evaluated) != len(h.merged) {
		copy(b, h.merged)
		return
	}
	copy(b, evaluated)
}

func (h *udpCustomClient) Match(b []byte) bool {
	var initial map[string][]byte
	if h.state != nil {
		initial, _ = h.state.get(udpStateKey(h.addr))
	}
	vars, ok := matchUDPItems(h.server, b, h.read, initial)
	if ok {
		h.vars = vars
		if h.state != nil {
			h.state.set(udpStateKey(h.addr), vars)
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

func (c *udpCustomClientConn) Size() int {
	return len(c.header.merged)
}

func (c *udpCustomClientConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !c.header.Match(p) {
		return 0, addr, errors.New("header mismatch")
	}

	return len(p) - c.header.read, addr, nil
}

func (c *udpCustomClientConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var localAddr net.Addr
	if c.PacketConn != nil {
		localAddr = c.PacketConn.LocalAddr()
	}
	ctx := newEvalContextWithAddrs(localAddr, addr)
	if vars, ok := c.header.state.get(udpStateKey(addr)); ok {
		ctx.vars = cloneVars(vars)
	} else if len(c.header.vars) > 0 {
		ctx.vars = cloneVars(c.header.vars)
	}
	evaluated, err := evaluateUDPItemsWithContext(c.header.client, ctx)
	if err != nil {
		return 0, err
	}
	if len(evaluated) != len(c.header.merged) {
		return 0, errors.New("header size mismatch")
	}
	c.header.state.set(udpStateKey(addr), ctx.vars)
	copy(p, evaluated)

	return len(p), nil
}

func (c *udpCustomClientConn) SetReadAddr(addr net.Addr) {
	c.header.addr = addr
}

type udpCustomServer struct {
	client []*UDPItem
	server []*UDPItem
	merged []byte
	read   int
	addr   net.Addr
	state  *stateStore
	vars   map[string][]byte
}

func (h *udpCustomServer) Serialize(b []byte) {
	evaluated, err := evaluateUDPItems(h.server)
	if err != nil || len(evaluated) != len(h.merged) {
		copy(b, h.merged)
		return
	}
	copy(b, evaluated)
}

func (h *udpCustomServer) Match(b []byte) bool {
	var initial map[string][]byte
	if h.state != nil {
		initial, _ = h.state.get(udpStateKey(h.addr))
	}
	vars, ok := matchUDPItems(h.client, b, h.read, initial)
	if ok {
		h.vars = vars
		if h.state != nil {
			h.state.set(udpStateKey(h.addr), vars)
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

func (c *udpCustomServerConn) Size() int {
	return len(c.header.merged)
}

func (c *udpCustomServerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if !c.header.Match(p) {
		return 0, addr, errors.New("header mismatch")
	}

	return len(p) - c.header.read, addr, nil
}

func (c *udpCustomServerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var localAddr net.Addr
	if c.PacketConn != nil {
		localAddr = c.PacketConn.LocalAddr()
	}
	ctx := newEvalContextWithAddrs(localAddr, addr)
	if vars, ok := c.header.state.get(udpStateKey(addr)); ok {
		ctx.vars = cloneVars(vars)
	} else if len(c.header.vars) > 0 {
		ctx.vars = cloneVars(c.header.vars)
	}
	evaluated, err := evaluateUDPItemsWithContext(c.header.server, ctx)
	if err != nil {
		return 0, err
	}
	if len(evaluated) != len(c.header.merged) {
		return 0, errors.New("header size mismatch")
	}
	c.header.state.set(udpStateKey(addr), ctx.vars)
	copy(p, evaluated)

	return len(p), nil
}

func (c *udpCustomServerConn) SetReadAddr(addr net.Addr) {
	c.header.addr = addr
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
	done chan error
}

func NewConnClientUDPStandalone(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
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
		waiter := c.registerWaiter(key, ctx.vars)
		if _, err := c.PacketConn.WriteTo(request, addr); err != nil {
			c.unregisterWaiter(key, waiter)
			return 0, err
		}
		if err := <-waiter.done; err != nil {
			return 0, err
		}
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *udpCustomStandaloneClientConn) ensureReader() {
	c.once.Do(func() {
		go c.readerLoop(c.queue)
	})
}

func (c *udpCustomStandaloneClientConn) registerWaiter(key string, vars map[string][]byte) *udpStandaloneWaiter {
	waiter := &udpStandaloneWaiter{
		vars: cloneVars(vars),
		done: make(chan error, 1),
	}
	c.mu.Lock()
	c.wait[key] = waiter
	c.mu.Unlock()
	return waiter
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
	waiter.done <- nil
	return true
}

func (c *udpCustomStandaloneClientConn) failWaiters(err error) {
	c.mu.Lock()
	waiters := c.wait
	c.wait = make(map[string]*udpStandaloneWaiter)
	c.mu.Unlock()
	for _, waiter := range waiters {
		waiter.done <- err
	}
}

type udpCustomStandaloneServerConn struct {
	net.PacketConn
	client []*UDPItem
	server []*UDPItem
	state  *stateStore
	read   int
}

func NewConnServerUDPStandalone(c *UDPConfig, raw net.PacketConn) (net.PacketConn, error) {
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
