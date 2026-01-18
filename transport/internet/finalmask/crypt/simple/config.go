package simple

import (
	"net"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn) (net.PacketConn, error) {
	return NewConn(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn) (net.PacketConn, error) {
	return NewConn(c, raw)
}
