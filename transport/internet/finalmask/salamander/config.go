package salamander

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask/salamander/obfs"
)

func (c *Config) UDP() {
}

func (c *Config) WrapPacketConnClient(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	return obfs.NewConnClient(c.Password, raw, first, leaveSize)
}

func (c *Config) WrapPacketConnServer(raw net.PacketConn, first bool, leaveSize int32, end bool) (net.PacketConn, error) {
	return obfs.NewConnServer(c.Password, raw, first, leaveSize)
}
