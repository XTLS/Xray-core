package salamander

import (
	"net"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	return NewConnClient(c, raw, first, leaveSize)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	return NewConnServer(c, raw, first, leaveSize)
}
