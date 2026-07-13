package xmc

import (
	"fmt"
	"net"
)

func (c *Config) TCP() {
}

func (c *Config) WrapConnClient(conn net.Conn) (net.Conn, error) {
	cc, err := newClientConn(conn, c.Usernames, c.Password, c.RsaPublicKey, c.Hostname, c.Mode)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	cc, err := wrapConnServer(conn, c.Password, c.RsaPrivateKey, c.RsaPublicKey, c.Mode)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}
