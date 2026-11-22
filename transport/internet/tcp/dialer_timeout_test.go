package tcp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

func TestStalledTLSHandshakeClosesSocket(t *testing.T) {
	t.Parallel()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		buffer := make([]byte, 4096)
		for {
			if _, err := conn.Read(buffer); err != nil {
				closed <- err
				return
			}
		}
	}()
	addr := listener.Addr().(*stdnet.TCPAddr)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecuritySettings: &xtls.Config{ServerName: "localhost"},
	}
	start := time.Now()
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), settings)
	if err == nil {
		conn.Close()
		t.Fatal("stalled TLS handshake unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed < 7*time.Second || elapsed > 12*time.Second {
		t.Fatalf("handshake took %v", elapsed)
	}
	select {
	case err := <-closed:
		if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Fatal("peer socket was left open")
		}
	case <-time.After(time.Second):
		t.Fatal("peer socket was left open")
	}
}

func TestPlainTCPConnectionRemainsUsable(t *testing.T) {
	t.Parallel()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(conn, buffer); err == nil {
			conn.Write(buffer)
		}
	}()
	addr := listener.Addr().(*stdnet.TCPAddr)
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), &internet.MemoryStreamConfig{ProtocolName: "tcp", ProtocolSettings: &Config{}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 4)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "ping" {
		t.Fatalf("unexpected response %q", buffer)
	}
}

func TestTLSConnectionSurvivesSetupDeadline(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(9 * time.Second)
		w.Write([]byte("alive"))
	}))
	defer server.Close()
	addr := server.Listener.Addr().(*stdnet.TCPAddr)
	pin := sha256.Sum256(server.Certificate().Raw)
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecuritySettings: &xtls.Config{ServerName: "localhost", PinnedPeerCertSha256: [][]byte{pin[:]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("missing HTTP response")
	}
}

func TestStalledRealityHandshakeClosesSocket(t *testing.T) {
	t.Parallel()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		buffer := make([]byte, 4096)
		for {
			if _, err := conn.Read(buffer); err != nil {
				closed <- err
				return
			}
		}
	}()
	addr := listener.Addr().(*stdnet.TCPAddr)
	settings := &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecuritySettings: &reality.Config{
			ServerName: "localhost", Fingerprint: "chrome", PublicKey: key.PublicKey().Bytes(),
		},
	}
	start := time.Now()
	conn, err := Dial(context.Background(), xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), settings)
	if err == nil {
		conn.Close()
		t.Fatal("stalled REALITY unexpectedly succeeded")
	}
	elapsed := time.Since(start)
	if elapsed < 7*time.Second || elapsed > 12*time.Second {
		t.Fatalf("unexpected negotiation duration %v with error %v", elapsed, err)
	}
	select {
	case err := <-closed:
		if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Fatal("REALITY socket left open")
		}
	case <-time.After(time.Second):
		t.Fatal("REALITY socket left open")
	}
}

func TestTLSHandshakeRespectsParentCancellation(t *testing.T) {
	t.Parallel()
	listener, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		cancel()
		buffer := make([]byte, 4096)
		for {
			if _, err := conn.Read(buffer); err != nil {
				closed <- err
				return
			}
		}
	}()
	addr := listener.Addr().(*stdnet.TCPAddr)
	start := time.Now()
	conn, err := Dial(ctx, xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(addr.Port)), &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &Config{},
		SecuritySettings: &xtls.Config{ServerName: "localhost"},
	})
	if err == nil {
		conn.Close()
		t.Fatal("canceled TLS handshake unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("parent cancellation took %v", elapsed)
	}
	select {
	case err := <-closed:
		if timeout, ok := err.(stdnet.Error); ok && timeout.Timeout() {
			t.Fatal("canceled TLS handshake left peer socket open")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled TLS handshake left peer socket open")
	}
}
