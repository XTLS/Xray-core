package custom

import (
	"bytes"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

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
