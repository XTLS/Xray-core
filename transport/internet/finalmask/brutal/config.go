package brutal

import "net"

func (c *Config) TCP() {}

func (c *Config) WrapConnClient(raw net.Conn) (net.Conn, error) {
	return NewConn(c, raw)
}

func (c *Config) WrapConnServer(raw net.Conn) (net.Conn, error) {
	return NewConn(c, raw)
}
