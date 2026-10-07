package xdns

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

// Encrypted resolvers own their TCP connections. Plain UDP/TCP retain the
// branch's existing mask composition behavior.
func (c *Config) HandlesDial() bool {
	for _, resolver := range c.Resolvers {
		if resolver != nil && (resolver.Type == "dot" || resolver.Type == "doh") {
			return true
		}
	}
	return false
}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return NewClient(c, dialer)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	return NewServer(c, conn)
}
