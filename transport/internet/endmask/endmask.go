package endmask

import "net"

type Endmask interface {
	WrapConn(net.Conn) (net.Conn, error)
	WrapPacketConn(net.PacketConn) (net.PacketConn, error)
	Size() int32
	Serialize([]byte)
}
