package tls

import (
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

var _ buf.Writer = (*Conn)(nil)

type Conn struct {
	*tls.Conn
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func (c *Conn) NegotiatedProtocol() (name string, mutual bool) {
	state := c.ConnectionState()
	return state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}

type UConn struct {
	*utls.UConn
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

// WebsocketHandshake basically calls UConn.Handshake inside it but it will only send
// http/1.1 in its ALPN.
func (c *UConn) WebsocketHandshake() error {
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = []string{"http/1.1"}
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.Handshake()
}

func (c *UConn) NegotiatedProtocol() (name string, mutual bool) {
	state := c.ConnectionState()
	return state.NegotiatedProtocol, state.NegotiatedProtocolIsMutual
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func copyConfig(c *tls.Config) *utls.Config {
	return &utls.Config{
		RootCAs:            c.RootCAs,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
	}
}

var Fingerprints = map[string]*utls.ClientHelloID{
	"chrome":     &utls.HelloChrome_Auto,
	"firefox":    &utls.HelloFirefox_Auto,
	"safari":     &utls.HelloIOS_Auto,
	"randomized": &utls.HelloRandomized,
}

type Interface interface {
	net.Conn
	Handshake() error
	VerifyHostname(host string) error
	NegotiatedProtocol() (name string, mutual bool)
}
