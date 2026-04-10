package bayed

import (
	"net"

	libbayed "github.com/EvrkMs/bayed-tls/bayed"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

// Conn wraps a bayed-tls *libbayed.Conn to implement HandshakeAddress
// returning an Xray net.Address.
type Conn struct {
	*libbayed.Conn
}

// HandshakeAddress returns the SNI used during handshake as an Xray Address.
func (c *Conn) HandshakeAddress() xnet.Address {
	addr := c.Conn.HandshakeAddress()
	if addr == "" {
		return nil
	}
	return xnet.ParseAddress(addr)
}

// Server performs the server-side bayed-tls handshake.
// If the client is not a bayed-tls client, it returns ErrNotBayed (the
// connection has already been transparently proxied to the upstream).
func Server(c net.Conn, config *libbayed.ServerConfig) (net.Conn, error) {
	bayedConn, err := libbayed.Server(c, config)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: bayedConn}, nil
}

// Client performs the client-side bayed-tls handshake.
func Client(c net.Conn, config *libbayed.ClientConfig) (net.Conn, error) {
	bayedConn, err := libbayed.Client(c, config)
	if err != nil {
		return nil, errors.New("BAYED: client handshake failed").Base(err)
	}
	if config.Show {
		errors.LogInfo(nil, "BAYED: handshake OK, verified=", bayedConn.Verified, ", serverName=", bayedConn.ServerName)
	}
	return &Conn{Conn: bayedConn}, nil
}
