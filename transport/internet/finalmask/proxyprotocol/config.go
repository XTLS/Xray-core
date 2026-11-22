package proxyprotocol

import (
	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	version := c.Version
	if version == 0 {
		version = 2
	}
	if version != 1 && version != 2 {
		return nil, errors.New("PROXY protocol version must be 1 or 2")
	}
	source := conn.LocalAddr()
	if dialer != nil && dialer.Source != nil {
		source = dialer.Source
	}
	header := headerFromAddrs(byte(version), source, conn.RemoteAddr())
	if _, err := header.WriteTo(conn); err != nil {
		return nil, errors.New("failed to write PROXY protocol header").Base(err)
	}
	return conn, nil
}

func headerFromAddrs(version byte, source, destination net.Addr) *proxyproto.Header {
	// Preserve the client's IP and port when matching its address type to
	// the upstream transport for the PROXY header.
	switch destination.(type) {
	case *net.TCPAddr:
		if udpSource, ok := source.(*net.UDPAddr); ok {
			source = &net.TCPAddr{IP: udpSource.IP, Port: udpSource.Port, Zone: udpSource.Zone}
		}
	case *net.UDPAddr:
		if tcpSource, ok := source.(*net.TCPAddr); ok {
			source = &net.UDPAddr{IP: tcpSource.IP, Port: tcpSource.Port, Zone: tcpSource.Zone}
		}
	}
	return proxyproto.HeaderProxyFromAddrs(version, source, destination)
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return proxyproto.NewConn(conn, proxyproto.WithPolicy(proxyproto.REQUIRE)), nil
}
