package minecraft

import (
	"fmt"
	"net"
)

func (c *Config) TCP() {
}

func (c *Config) WrapConnClient(conn net.Conn) (net.Conn, error) {
	cc, err := newClientConn(conn, c.Usernames, c.ShortId, c.PublicKeySha256, c.Addresss, uint16(c.Port))
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	cc, err := wrapConnServer(conn, c.ShortIds, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}
