package finalmask

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/errors"
)

const (
	UDPSize = 4096 + 123
)

type Udpmask interface {
	UDP()

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
	var err error
	for i, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnClient(raw, i, len(m.udpmasks)-1)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	var err error
	for i, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnServer(raw, i, len(m.udpmasks)-1)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

type Tcpmask interface {
	TCP()

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
	for _, mask := range m.tcpmasks {
		raw, err = mask.WrapConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *TcpmaskManager) WrapConnServer(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range m.tcpmasks {
		raw, err = mask.WrapConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

type Listener struct {
	m *TcpmaskManager
	net.Listener
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	newConn, err := l.m.WrapConnServer(conn)
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "mask err")
		conn.Close()
		return nil, err
	}

	conn = newConn
	return conn, nil
}

func (m *TcpmaskManager) WrapConnListener(listener net.Listener) (net.Listener, error) {
	return &Listener{
		m:        m,
		Listener: listener,
	}, nil
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
