package salamander

import (
	"net"

	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) HeaderConn() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewSalamanderConnClient(c, conn)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewSalamanderConnServer(c, conn)
}

func (c *GeckoConfig) WrapPacketConnClient(conn net.PacketConn, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewGeckoConnClient(c, conn)
}

func (c *GeckoConfig) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewGeckoConnServer(c, conn)
}
