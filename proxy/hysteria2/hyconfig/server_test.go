package hyconfig

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Minimal regression test: userpass auth should accept "user:pass".
func TestServerConfigUserPassAuth(t *testing.T) {
	cfg := &ServerConfig{
		Auth: ServerAuthConfig{
			Type: "userpass",
			UserPass: map[string]string{
				"user": "pass",
			},
		},
	}
	// Use stream TLS to skip cert/key requirements.
	hysCfg, err := cfg.Build(dummyPacketConn(t), BuildOptions{
		UseTLSFromStream: true,
		StreamTLS:        &tls.Config{},
	})
	require.NoError(t, err)
	require.NotNil(t, hysCfg.Authenticator)

	ok, id := hysCfg.Authenticator.Authenticate(&net.IPAddr{}, "user:pass", 0)
	require.True(t, ok)
	require.Equal(t, "user", id)
}

func dummyPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	// Keep it short-lived; caller closes if needed.
	_ = pc.SetDeadline(time.Now().Add(5 * time.Second))
	return pc
}
