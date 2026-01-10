package endmask

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/endmask/udphop"
)

type Endmask interface {
	WrapConnClient(net.Conn) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)

	WrapPacketConnClient(net.PacketConn) (net.PacketConn, error)
	WrapPacketConnServer(net.PacketConn) (net.PacketConn, error)

	Size() int32
	Serialize([]byte)
}

type EndmaskManager struct {
	udphop   *udphop.Config
	endmasks []Endmask
}

func NewEndmaskManager(udphop *udphop.Config, endmasks []Endmask) *EndmaskManager {
	return &EndmaskManager{
		udphop:   udphop,
		endmasks: endmasks,
	}
}

func (e *EndmaskManager) WrapConnClient(raw net.Conn) (net.Conn, error) {
	var err error
	for _, endmask := range e.endmasks {
		raw, err = endmask.WrapConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (e *EndmaskManager) WrapConnServer(raw net.Conn) (net.Conn, error) {
	var err error
	for _, endmask := range e.endmasks {
		raw, err = endmask.WrapConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (e *EndmaskManager) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	var err error
	for _, endmask := range e.endmasks {
		raw, err = endmask.WrapPacketConnClient(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (e *EndmaskManager) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	var err error
	for _, endmask := range e.endmasks {
		raw, err = endmask.WrapPacketConnServer(raw)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}

func (e *EndmaskManager) Size() int32 {
	if len(e.endmasks) > 0 {
		return e.endmasks[0].Size()
	}
	return 0
}

func (e *EndmaskManager) Serialize(b []byte) {
	if len(e.endmasks) > 0 {
		e.endmasks[0].Serialize(b)
	}
}

func (e *EndmaskManager) GetUdpHop() *udphop.Config {
	return e.udphop
}
