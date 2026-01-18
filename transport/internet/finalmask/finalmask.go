package finalmask

import (
	"net"
)

type ConnSize interface {
	Size() int32
}

type Udpmask interface {
	UDP()

	WrapPacketConnClient(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error)
	WrapPacketConnServer(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error)
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
	leaveSize := int32(0)
	var err error
	for i, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnClient(raw, i == len(m.udpmasks)-1, leaveSize, i == 0)
		if err != nil {
			return nil, err
		}
		leaveSize += raw.(ConnSize).Size()
	}
	return raw, nil
}

func (m *UdpmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	leaveSize := int32(0)
	var err error
	for i, mask := range m.udpmasks {
		raw, err = mask.WrapPacketConnServer(raw, i == len(m.udpmasks)-1, leaveSize, i == 0)
		if err != nil {
			return nil, err
		}
		leaveSize += raw.(ConnSize).Size()
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
