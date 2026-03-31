package xdns

import (
	"net"

	"github.com/xtls/xray-core/common/errors"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	if len(c.Resolvers) > 0 && level > 0 {
		return nil, errors.New("xdns resolver mode cannot be combined with lower finalmask layers because resolver traffic must be valid DNS on the wire")
	}
	return NewConnClient(c, raw)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, level int, levelCount int) (net.PacketConn, error) {
	return NewConnServer(c, raw)
}
