package minecraft

import (
	"net"
)

func (c *Config) TCP() {
}

func (c *Config) WrapConnClient(net.Conn) (net.Conn, error) {
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	return wrapConnServer(conn, c.ShortIds, c.PrivateKey)
}
