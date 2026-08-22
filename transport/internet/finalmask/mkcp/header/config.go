package header

import (
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) UDP() {}

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw finalmask.PacketConn, level int, levelCount int) (finalmask.PacketConn, error) {
	return NewConnServer(c, raw)
}
