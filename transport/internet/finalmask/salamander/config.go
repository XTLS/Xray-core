package salamander

import (
	"net"
)

func (c *Config) UDP() {}

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewSalamanderConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewSalamanderConnServer(c, raw)
}
