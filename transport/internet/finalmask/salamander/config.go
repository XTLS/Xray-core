package salamander

import (
	"net"
)

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewSalamanderConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewSalamanderConnServer(c, raw)
}

func (c *GeckoConfig) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewGeckoConnClient(c, raw)
}

func (c *GeckoConfig) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewGeckoConnServer(c, raw)
}
