package xdns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewConnClientWithDialer(c, conn, dialer)
}

// HandlesDial makes XDNS allocate its own resolver connections only when an
// encrypted resolver is configured. Pure UDP keeps the existing PacketConn
// wrapping behavior and mask composition.
func (c *Config) HandlesDial() bool {
	return hasEncryptedResolver(c.Resolvers)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	return NewConnServer(c, conn)
}
