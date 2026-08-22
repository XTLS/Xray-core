package custom

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *TCPConfig) TCP() {}

func (c *TCPConfig) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return NewConnClientTCP(c, raw)
}

func (c *TCPConfig) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return NewConnServerTCP(c, raw)
}

func (c *UDPConfig) UDP() {}

func (c *UDPConfig) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnClientUDP(c, raw)
}

func (c *UDPConfig) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnServerUDP(c, raw)
}

func (c *UDPStandaloneConfig) UDP() {}

func (c *UDPStandaloneConfig) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnClientUDPStandalone(c, raw)
}

func (c *UDPStandaloneConfig) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnServerUDPStandalone(c, raw)
}
