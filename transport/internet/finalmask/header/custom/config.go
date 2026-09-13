package custom

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *TCPConfig) WrapConnClient(conn net.Conn, dialer *finalmask.Dialer) (net.Conn, error) {
	return NewConnClientTCP(c, conn)
}

func (c *TCPConfig) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return NewConnServerTCP(c, conn)
}

func (c *UDPConfig) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewConnClientUDP(c, conn)
}

func (c *UDPConfig) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewConnServerUDP(c, conn)
}

func (c *UDPStandaloneConfig) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewConnClientUDPStandalone(c, conn)
}

func (c *UDPStandaloneConfig) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewConnServerUDPStandalone(c, conn)
}
