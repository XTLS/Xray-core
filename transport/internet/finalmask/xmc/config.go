package xmc

import (
	"fmt"
	"net"
)

func (c *Config) TCP() {
}

func (c *Config) WrapConnClient(conn net.Conn) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := newClientConn(conn, profiles, c.Password, c.RsaPublicKey, c.Hostname)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}

func (c *Config) WrapConnServer(conn net.Conn) (net.Conn, error) {
	profiles, err := profilesFromConfig(c.Profiles)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}
	cc, err := wrapConnServer(conn, profiles, c.Password, c.RsaPrivateKey, c.RsaPublicKey)
	if err != nil {
		return nil, fmt.Errorf("minecraft finalmask: %w", err)
	}

	return cc, nil
}
