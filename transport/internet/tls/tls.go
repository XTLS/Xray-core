package tls

import (
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

var (
	_ buf.Writer = (*Conn)(nil)
)

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

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

func copyConfig(c *tls.Config) *utls.Config {
	//return &utls.Config{
	//	NextProtos:         c.NextProtos,
	//	ServerName:         c.ServerName,
	//	InsecureSkipVerify: c.InsecureSkipVerify,
	//	MinVersion:         c.MinVersion,
	//	MaxVersion:         c.MaxVersion,
	//}
	return &utls.Config{
		RootCAs:                  c.RootCAs,
		NextProtos:               c.NextProtos,
		ServerName:               c.ServerName,
		InsecureSkipVerify:       c.InsecureSkipVerify,
		CipherSuites:             c.CipherSuites,
		PreferServerCipherSuites: c.PreferServerCipherSuites,
		SessionTicketsDisabled:   c.SessionTicketsDisabled,
		MinVersion:               c.MinVersion,
		MaxVersion:               c.MaxVersion,
	}
}

func GetuTLSClientHelloID(name string) (*utls.ClientHelloID, error) {
	switch name {
	case "chrome":
		return &utls.HelloChrome_Auto, nil
	case "firefox":
		return &utls.HelloFirefox_Auto, nil
	case "safari":
		return &utls.HelloIOS_Auto, nil
	case "randomized":
		return &utls.HelloRandomized, nil
	default:
		return nil, newError("invalid fingerprint: " + name)
	}
}

func UClient(c net.Conn, config *tls.Config, clientHelloID utls.ClientHelloID) net.Conn {
	uConfig := copyConfig(config)
	conn := utls.UClient(c, uConfig, clientHelloID)
	conn.Handshake()
	return conn
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}
