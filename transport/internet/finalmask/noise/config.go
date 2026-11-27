package noise

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	wrapped, err := NewConnClient(c, conn)
	if err == nil && dialer != nil {
		wrapped.(*noiseConn).path = dialer.UDPPath
	}
	return wrapped, err
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	return NewConnServer(c, conn)
}
