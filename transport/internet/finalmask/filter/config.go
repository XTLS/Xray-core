package filter

import (
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) buildFilter() (*filter, error) {
	if len(c.BlockedSourceIps) == 0 && len(c.AllowedSourceIps) == 0 {
		return nil, nil
	}
	f := new(filter)
	var err error
	if len(c.BlockedSourceIps) > 0 {
		f.blocked, err = geodata.IPReg.BuildIPMatcher(c.BlockedSourceIps)
		if err != nil {
			return nil, err
		}
	}
	if len(c.AllowedSourceIps) > 0 {
		f.allowed, err = geodata.IPReg.BuildIPMatcher(c.AllowedSourceIps)
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (c *Config) Listen(inner net.Listener) (net.Listener, error) {
	f, err := c.buildFilter()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return inner, nil
	}
	return &listener{Listener: inner, filter: f}, nil
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
	f, err := c.buildFilter()
	if err != nil {
		return nil, err
	}
	if f == nil {
		return conn, nil
	}
	return &packetConn{PacketConn: conn, filter: f}, nil
}
