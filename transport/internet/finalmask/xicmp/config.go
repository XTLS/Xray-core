package xicmp

import (
	"errors"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) HandleDial() {}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	if dest.Address.Family().IsDomain() && len(c.IPs) == 0 {
		return nil, errors.New("empty ip addresses")
	}
	return NewConnClient(c, conn)
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn) (net.PacketConn, error) {
	return NewConnServer(c, conn)
}
