package finalmask

import (
	"net"
)

type Udpmask interface {
	UDP()

	WrapConnClient(net.Conn) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)

	WrapPacketConnClient(net.PacketConn) (net.PacketConn, error)
	WrapPacketConnServer(net.PacketConn) (net.PacketConn, error)

	Size() int
	Serialize([]byte)
}

type UdpmaskManager struct {
	udpmasks []Udpmask
}

func NewUdpmaskManager(udpmasks []Udpmask) *UdpmaskManager {
	return &UdpmaskManager{
		udpmasks: udpmasks,
	}
}

func (m *UdpmaskManager) WrapConnClient(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range m.udpmasks {
		raw, err = mask.WrapConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapConnServer(raw net.Conn) (net.Conn, error) {
	var err error
	for _, mask := range m.udpmasks {
		raw, err = mask.WrapConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	var err error
	for _, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	var err error
	for _, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (m *UdpmaskManager) Size() int {
	size := 0
	for _, mask := range m.udpmasks {
		size += mask.Size()
	}
	return size
}

func (m *UdpmaskManager) Serialize(b []byte) {
	index := 0
	for _, mask := range m.udpmasks {
		mask.Serialize(b[index:])
		index += mask.Size()
	}
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
