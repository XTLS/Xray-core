package finalmask

import (
	"context"
	"net"
	"slices"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type Udpmask interface {
	WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error)
	WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error)
}

type UdpmaskManager struct {
	udpmasks []Udpmask
}

func NewUdpmaskManager(udpmasks []Udpmask) *UdpmaskManager {
	return &UdpmaskManager{
		udpmasks: udpmasks,
	}
}

func (m *UdpmaskManager) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	var sizes []int
	var conns []net.PacketConn
	for i, mask := range slices.Backward(m.udpmasks) {
		if _, ok := mask.(headerConn); ok {
			conn, err := mask.WrapPacketConnClient(nil, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
			sizes = append(sizes, conn.(headerSize).Size())
			conns = append(conns, conn)
		} else {
			if len(conns) > 0 {
				raw = &headerManagerConn{sizes: sizes, conns: conns, PacketConn: raw}
				sizes = nil
				conns = nil
			}
			var err error
			raw, err = mask.WrapPacketConnClient(raw, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(conns) > 0 {
		raw = &headerManagerConn{sizes: sizes, conns: conns, PacketConn: raw}
		sizes = nil
		conns = nil
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	var sizes []int
	var conns []net.PacketConn
	for i, mask := range slices.Backward(m.udpmasks) {
		if _, ok := mask.(headerConn); ok {
			conn, err := mask.WrapPacketConnServer(nil, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
			sizes = append(sizes, conn.(headerSize).Size())
			conns = append(conns, conn)
		} else {
			if len(conns) > 0 {
				raw = &headerManagerConn{sizes: sizes, conns: conns, PacketConn: raw}
				sizes = nil
				conns = nil
			}
			var err error
			raw, err = mask.WrapPacketConnServer(raw, i, len(m.udpmasks)-1)
			if err != nil {
				return nil, err
			}
		}
	}

	if len(conns) > 0 {
		raw = &headerManagerConn{sizes: sizes, conns: conns, PacketConn: raw}
		sizes = nil
		conns = nil
	}
	return raw, nil
}

const (
	UDPSize = 4096
)

type headerConn interface {
	HeaderConn()
}

type headerSize interface {
	Size() int
}

type headerManagerConn struct {
	net.PacketConn

	sizes []int
	conns []net.PacketConn
}

func (c *headerManagerConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	b := p
	if len(b) < UDPSize {
		buf := buf.New()
		buf.Resize(0, UDPSize)
		b = buf.Bytes()
		defer buf.Release()
	}

	for {
		n, addr, err = c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, addr, err
		}
		buf := b[:n]

		sum := 0
		for _, size := range c.sizes {
			sum += size
		}

		if n < sum {
			errors.LogError(context.Background(), "[mask] drop packet from ", addr, " with size ", n)
			continue
		}

		for i := range c.conns {
			n, _, err = c.conns[i].ReadFrom(buf)
			if err != nil {
				errors.LogErrorInner(context.Background(), err, "[mask] drop packet from ", addr, " with size ", n)
				break
			}
			buf = buf[c.sizes[i] : n+c.sizes[i]]
		}

		if err != nil {
			continue
		}

		return copy(p, buf), addr, nil
	}
}

func (c *headerManagerConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buf := buf.New()
	buf.Resize(0, UDPSize)
	b := buf.Bytes()
	defer buf.Release()

	sum := 0
	for _, size := range c.sizes {
		sum += size
	}

	if sum+len(p) > UDPSize {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	n = copy(b[sum:], p)

	for i := len(c.conns) - 1; i >= 0; i-- {
		n, err = c.conns[i].WriteTo(b[sum-c.sizes[i]:n+sum], nil)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "[mask] drop packet to ", addr, " with size ", len(p))
			return 0, nil
		}
		sum -= c.sizes[i]
	}

	if n > UDPSize {
		errors.LogError(context.Background(), "[mask] drop packet to ", addr, " with size ", len(p))
		return 0, nil
	}

	_, err = c.PacketConn.WriteTo(b[:n], addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

type Tcpmask interface {
	WrapConnClient(net.Conn) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)
}

type TcpmaskManager struct {
	tcpmasks []Tcpmask
}

func NewTcpmaskManager(tcpmasks []Tcpmask) *TcpmaskManager {
	return &TcpmaskManager{
		tcpmasks: tcpmasks,
	}
}

func (m *TcpmaskManager) WrapConnClient(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range slices.Backward(m.tcpmasks) {
		raw, err = mask.WrapConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *TcpmaskManager) WrapConnServer(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range slices.Backward(m.tcpmasks) {
		raw, err = mask.WrapConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *TcpmaskManager) WrapListener(l net.Listener) (net.Listener, error) {
	return NewTcpListener(m, l)
}

type tcpListener struct {
	m *TcpmaskManager
	net.Listener
}

func NewTcpListener(m *TcpmaskManager, l net.Listener) (net.Listener, error) {
	return &tcpListener{
		m:        m,
		Listener: l,
	}, nil
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	newConn, err := l.m.WrapConnServer(conn)
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "mask err")
		_ = conn.Close()
		return nil, err
	}

	return newConn, nil
}

type TcpMaskConn interface {
	TcpMaskConn()
	RawConn() net.Conn
	Splice() bool
}

func UnwrapTcpMask(conn net.Conn) net.Conn {
	for {
		if v, ok := conn.(TcpMaskConn); ok {
			if !v.Splice() {
				return conn
			}
			conn = v.RawConn()
		} else {
			return conn
		}
	}
}
