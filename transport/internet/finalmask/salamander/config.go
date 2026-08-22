package salamander

import (
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) UDP() {}

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewSalamanderConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewSalamanderConnServer(c, raw)
}

func (c *GeckoConfig) UDP() {}

func (c *GeckoConfig) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewGeckoConnClient(c, raw)
}

func (c *GeckoConfig) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewGeckoConnServer(c, raw)
}
