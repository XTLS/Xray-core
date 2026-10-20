package ipfilter

import (
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) matcher() (geodata.IPMatcher, error) {
	if len(c.BlockedIps) == 0 {
		return nil, nil
	}
	return geodata.IPReg.BuildIPMatcher(c.BlockedIps)
}

func (c *Config) Listen(inner net.Listener) (net.Listener, error) {
	matcher, err := c.matcher()
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return inner, nil
	}
	return &listener{Listener: inner, matcher: matcher}, nil
}

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	return conn, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	// TCP filtering is installed by Listen, before per-connection masks.
	return conn, nil
}

func (c *Config) WrapPacketConnClient(conn net.PacketConn, dest *net.Destination, dialer *finalmask.Dialer) (net.PacketConn, error) {
	return conn, nil
}

func (c *Config) WrapPacketConnServer(conn net.PacketConn, addr net.Addr, lc *finalmask.ListenConfig) (net.PacketConn, error) {
	matcher, err := c.matcher()
	if err != nil {
		return nil, err
	}
	if matcher == nil {
		return conn, nil
	}
	return &packetConn{PacketConn: conn, matcher: matcher}, nil
}
