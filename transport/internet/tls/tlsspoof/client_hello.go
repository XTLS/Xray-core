package tlsspoof

import (
	"bytes"
	"context"
	"crypto/tls"

	"errors"
	"net"
	"time"
)

type writeOnlyConn struct {
	net.Conn
	w *bytes.Buffer
}

func (c *writeOnlyConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *writeOnlyConn) Read(b []byte) (int, error) {
	return 0, errors.New("read from write-only conn")
}

func (c *writeOnlyConn) Close() error {
	return nil
}

func (c *writeOnlyConn) LocalAddr() net.Addr {
	return nil
}

func (c *writeOnlyConn) RemoteAddr() net.Addr {
	return nil
}

func (c *writeOnlyConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *writeOnlyConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *writeOnlyConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// buildFakeClientHello drives crypto/tls against a write-only in-memory conn
// to capture a generated ClientHello. CurvePreferences pins classical groups
// to suppress Go's default X25519MLKEM768 hybrid key share; without this the
// post-quantum public key alone (~1184 bytes) pushes the record past one MSS,
// and middleboxes do not reassemble fragmented ClientHellos. The handshake
// error is discarded because the stub conn's Read returns immediately.
func buildFakeClientHello(sni string) ([]byte, error) {
	if sni == "" {
		return nil, errors.New("empty sni")
	}
	var buf bytes.Buffer
	tlsConn := tls.Client(&writeOnlyConn{w: &buf}, &tls.Config{
		ServerName: sni,
		// Order matches what browsers advertised before post-quantum.
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true,
	})
	_ = tlsConn.HandshakeContext(context.Background())
	if buf.Len() == 0 {
		return nil, errors.New("tls ClientHello not produced")
	}
	return buf.Bytes(), nil
}
