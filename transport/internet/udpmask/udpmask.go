package udpmask

import (
	"net"
)

type Udpmask interface {
	WrapConnClient(net.Conn) (net.Conn, error)
	WrapConnServer(net.Conn) (net.Conn, error)

	WrapPacketConnClient(net.PacketConn) (net.PacketConn, error)
	WrapPacketConnServer(net.PacketConn) (net.PacketConn, error)

	Size() int32
	Serialize([]byte)
}
