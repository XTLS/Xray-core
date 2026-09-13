package header

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewConnClient(c, conn)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewConnServer(c, conn)
}
