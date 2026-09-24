package tcp_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"runtime/debug"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	. "github.com/xtls/xray-core/transport/internet/tcp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// serveNonTLS answers the first read with a plain HTTP error, then reports
// whether the client closed its end (nil) or left it open (a timeout error).
func serveNonTLS(t *testing.T) (net.Destination, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	result := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		b := make([]byte, 4096)
		conn.Read(b) // ClientHello
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			if _, err := conn.Read(b); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					result <- err
				} else {
					result <- nil
				}
				return
			}
		}
	}()
	return net.DestinationFromAddr(l.Addr()), result
}

func TestDialClosesConnOnHandshakeFailure(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]interface{}{
		"tls":     &tls.Config{ServerName: "example.com"},
		"utls":    &tls.Config{ServerName: "example.com", Fingerprint: "chrome"},
		"reality": &reality.Config{ServerName: "example.com", Fingerprint: "chrome", PublicKey: key.PublicKey().Bytes()},
	}
	for name, security := range cases {
		t.Run(name, func(t *testing.T) {
			dest, result := serveNonTLS(t)
			streamSettings := &internet.MemoryStreamConfig{
				ProtocolName:     "tcp",
				ProtocolSettings: &Config{},
				SecuritySettings: security,
			}
			if _, err := Dial(context.Background(), dest, streamSettings); err == nil {
				t.Fatal("expected handshake error")
			}
			if err := <-result; err != nil {
				t.Fatal("client did not close the connection:", err)
			}
		})
	}
}
