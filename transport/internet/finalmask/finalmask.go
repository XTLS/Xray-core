package finalmask

import (
	"context"
	"fmt"
	"slices"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

type Dialer struct {
	DialTCP func(net.Destination) (net.Conn, error)
	DialUDP func(net.Destination) (net.PacketConn, error)
}

type TCPMask interface {
	WrapConnClient(net.Conn, *Dialer) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)
}

type UDPMask interface {
	WrapPacketConnClient(net.PacketConn, *Dialer) (net.PacketConn, error)
	WrapPacketConnServer(net.PacketConn) (net.PacketConn, error)
}

type FinalMask struct {
	tcpMasks     []TCPMask
	udpMasks     []UDPMask
	dialTCP      func(context.Context, net.Destination) (net.Conn, error)
	listen       func(context.Context, net.Addr) (net.Listener, error)
	dialUDP      func(context.Context, net.Destination) (net.PacketConn, error)
	listenPacket func(context.Context, net.Addr) (net.PacketConn, error)
}

func NewFinalMask(tcpMasks []TCPMask, udpMasks []UDPMask, dialTCP func(context.Context, net.Destination) (net.Conn, error), listen func(context.Context, net.Addr) (net.Listener, error), dialUDP func(context.Context, net.Destination) (net.PacketConn, error), listenPacket func(context.Context, net.Addr) (net.PacketConn, error)) *FinalMask {
	slices.Reverse(tcpMasks)
	slices.Reverse(udpMasks)
	return &FinalMask{
		tcpMasks:     tcpMasks,
		udpMasks:     udpMasks,
		dialTCP:      dialTCP,
		dialUDP:      dialUDP,
		listen:       listen,
		listenPacket: listenPacket,
	}
}

func (fm *FinalMask) DialTCP(ctx context.Context, dest net.Destination) (net.Conn, error) {
	if len(fm.tcpMasks) == 0 {
		return fm.dialTCP(ctx, dest)
	}
	for i := range fm.tcpMasks {
		if i > 0 {
			if _, ok := fm.tcpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.tcpMasks[i])
			}
		}
	}
	var conn net.Conn
	var err error
	if _, ok := fm.tcpMasks[0].(interface{ HandleDial() }); !ok {
		conn, err = fm.dialTCP(ctx, dest)
		if err != nil {
			return nil, err
		}
	}
	dialer := &Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return fm.dialTCP(ctx, dest)
		},
		DialUDP: func(dest net.Destination) (net.PacketConn, error) {
			return fm.dialUDP(ctx, dest)
		},
	}
	for i := range fm.tcpMasks {
		var newConn net.Conn
		newConn, err = fm.tcpMasks[i].WrapConnClient(conn, dialer)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = newConn
	}
	return conn, nil
}

func (fm *FinalMask) Listen(ctx context.Context, addr net.Addr) (net.Listener, error) {
	if len(fm.tcpMasks) == 0 {
		return fm.listen(ctx, addr)
	}
	for i := range fm.tcpMasks {
		if i > 0 {
			if _, ok := fm.tcpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.tcpMasks[i])
			}
		}
	}
	listener, err := fm.listen(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &TCPListener{Listener: listener, tcpMasks: fm.tcpMasks}, nil
}

func (fm *FinalMask) DialUDP(ctx context.Context, dest net.Destination) (net.PacketConn, error) {
	if len(fm.udpMasks) == 0 {
		return fm.dialUDP(ctx, dest)
	}
	for i := range fm.udpMasks {
		if i > 0 {
			if _, ok := fm.udpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.udpMasks[i])
			}
		}
	}
	var conn net.PacketConn
	var err error
	if _, ok := fm.udpMasks[0].(interface{ HandleDial() }); !ok {
		conn, err = fm.dialUDP(ctx, dest)
		if err != nil {
			return nil, err
		}
	}
	dialer := &Dialer{
		DialTCP: func(dest net.Destination) (net.Conn, error) {
			return fm.dialTCP(ctx, dest)
		},
		DialUDP: func(dest net.Destination) (net.PacketConn, error) {
			return fm.dialUDP(ctx, dest)
		},
	}
	var sizes []int
	var conns []net.PacketConn
	for i := range fm.udpMasks {
		var newConn net.PacketConn
		if _, ok := fm.udpMasks[i].(interface{ HeaderConn() }); ok {
			newConn, err = fm.udpMasks[i].WrapPacketConnClient(nil, nil)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			sizes = append(sizes, newConn.(interface{ Size() int }).Size())
			conns = append(conns, newConn)
		} else {
			if len(conns) > 0 {
				conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
				sizes = nil
				conns = nil
			}
			newConn, err = fm.udpMasks[i].WrapPacketConnClient(conn, dialer)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = newConn
		}
	}
	if len(conns) > 0 {
		conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
		sizes = nil
		conns = nil
	}
	return conn, nil
}

func (fm *FinalMask) ListenPacket(ctx context.Context, addr net.Addr) (net.PacketConn, error) {
	if len(fm.udpMasks) == 0 {
		return fm.listenPacket(ctx, addr)
	}
	for i := range fm.udpMasks {
		if i > 0 {
			if _, ok := fm.udpMasks[i].(interface{ HandleDial() }); ok {
				return nil, fmt.Errorf("incorrect index: %d %T", i, fm.udpMasks[i])
			}
		}
	}
	conn, err := fm.listenPacket(ctx, addr)
	if err != nil {
		return nil, err
	}
	var sizes []int
	var conns []net.PacketConn
	for i := range fm.udpMasks {
		var newConn net.PacketConn
		if _, ok := fm.udpMasks[i].(interface{ HeaderConn() }); ok {
			newConn, err = fm.udpMasks[i].WrapPacketConnServer(nil)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			sizes = append(sizes, newConn.(interface{ Size() int }).Size())
			conns = append(conns, newConn)
		} else {
			if len(conns) > 0 {
				conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
				sizes = nil
				conns = nil
			}
			newConn, err = fm.udpMasks[i].WrapPacketConnServer(conn)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = newConn
		}
	}
	if len(conns) > 0 {
		conn = &headerManagerConn{PacketConn: conn, sizes: sizes, conns: conns}
		sizes = nil
		conns = nil
	}
	return conn, nil
}

const (
	UDPSize = 4096
)

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

type TCPListener struct {
	net.Listener
	tcpMasks []TCPMask
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	for i := range l.tcpMasks {
		var newConn net.Conn
		newConn, err = l.tcpMasks[i].WrapConnServer(conn)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = newConn
	}
	return conn, nil
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
