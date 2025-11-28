package hysteria2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/xtls/xray-core/proxy/hysteria2/hyconfig"
	hyclient "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/client"
	hyserver "github.com/xtls/xray-core/proxy/hysteria2/hycore/v2/server"
)

// recorderOutbound captures outbound TCP connections from the server.
type recorderOutbound struct {
	tcpCh chan net.Conn
}

func newRecorderOutbound() *recorderOutbound {
	return &recorderOutbound{tcpCh: make(chan net.Conn, 1)}
}

func (r *recorderOutbound) TCP(string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	r.tcpCh <- c1
	return c2, nil
}

func (r *recorderOutbound) UDP(string) (hyserver.UDPConn, error) {
	return nil, net.ErrWriteToConnected // not used in test
}

// testConnFactory dials a fresh UDP socket for the client.
type testConnFactory struct{}

func (testConnFactory) New(net.Addr) (net.PacketConn, error) {
	return net.ListenPacket("udp", "127.0.0.1:0")
}

// Build a TLS config with an in-memory self-signed cert.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}

// End-to-end handshake and TCP data exchange between client and server.
func TestHysteria2HandshakeAndTCP(t *testing.T) {
	tlsCfg := selfSignedTLSConfig(t)

	// Listen on a random UDP port.
	pconn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pconn.Close()

	outRec := newRecorderOutbound()

	// Build server config.
	srvCfg, err := (&hyconfig.ServerConfig{
		Auth: hyconfig.ServerAuthConfig{
			Type:     "password",
			Password: "pass123",
		},
	}).Build(pconn, hyconfig.BuildOptions{
		UseTLSFromStream: true,
		StreamTLS:        tlsCfg,
	})
	require.NoError(t, err)
	srvCfg.Outbound = outRec

	server, err := hyserver.NewServer(srvCfg)
	require.NoError(t, err)
	defer server.Close()

	// Start server.
	go func() {
		_ = server.Serve()
	}()

	// Build client config.
	clTLS := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		NextProtos:         []string{"h3"},
	}
	ccfg := &hyconfig.ClientConfig{
		Server: pconn.LocalAddr().String(),
		Auth:   "pass123",
	}
	ccfg.TLS.SNI = "localhost"
	ccfg.TLS.Insecure = true

	clientCfg, err := ccfg.Build(hyconfig.ClientBuildOptions{
		UseTLSFromStream: true,
		StreamTLS:        clTLS,
		ConnFactory:      &testConnFactory{},
	})
	require.NoError(t, err)

	client, _, err := hyclient.NewClient(clientCfg)
	require.NoError(t, err)
	defer client.Close()

	// Open TCP stream via Hysteria.
	hConn, err := client.TCP("example.com:80")
	require.NoError(t, err)
	defer hConn.Close()

	// Server outbound side should receive a connection.
	var outboundConn net.Conn
	select {
	case outboundConn = <-outRec.tcpCh:
	case <-time.After(2 * time.Second):
		t.Fatal("outbound conn not received")
	}
	defer outboundConn.Close()

	// Send data client -> server outbound.
	_, err = hConn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = outboundConn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("ping"), buf)

	// Send response back server -> client.
	_, err = outboundConn.Write([]byte("pong"))
	require.NoError(t, err)

	buf2 := make([]byte, 4)
	_, err = hConn.Read(buf2)
	require.NoError(t, err)
	require.Equal(t, []byte("pong"), buf2)
}
