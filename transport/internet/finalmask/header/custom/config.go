package custom

import (
	"net"
)

func (c *TCPConfig) TCP() {
}

func (c *TCPConfig) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return NewConnClientTCP(c, raw)
}

func (c *TCPConfig) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return NewConnServerTCP(c, raw)
}

func (c *UDPConfig) UDP() {
}

func (c *UDPConfig) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if c.Mode == "standalone" {
		return NewConnClientUDPStandalone(c, raw)
	}
	return NewConnClientUDP(c, raw)
}

func (c *UDPConfig) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if c.Mode == "standalone" {
		return NewConnServerUDPStandalone(c, raw)
	}
	return NewConnServerUDP(c, raw)
}

func (c *UDPConfig) HeaderConn() {
}

func (c *UDPConfig) UseHeaderConn() bool {
	return c.Mode != "standalone"
}
