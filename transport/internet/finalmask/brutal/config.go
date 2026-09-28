package brutal

import (
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func (c *Config) WrapConnClient(conn net.Conn, dest *net.Destination, dialer *finalmask.Dialer) (net.Conn, error) {
	return NewConn(c, conn)
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return NewConn(c, conn)
}
