package splithttp_test

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestH3PacketUpAtStreamLimit(t *testing.T) {
	certificate, hash := cert.MustGenerate(nil, cert.DNSNames("localhost"))
	serverCert := tls.ParseCertificate(certificate)
	serverCert.OneTimeLoading = true
	server := &internet.MemoryStreamConfig{
		ProtocolSettings: &splithttp.Config{Mode: "packet-up"},
		SecuritySettings: &tls.Config{
			Certificate:  []*tls.Certificate{serverCert},
			NextProtocol: []string{"h3"},
		},
		SecurityType: "tls",
		QuicParams:   &internet.QuicParams{MaxIncomingStreams: 2, Congestion: "reno"},
	}
	peers := make(chan string, 3)
	listener, err := splithttp.ListenXH(t.Context(), net.LocalHostIP, 0, server, func(conn stat.Connection) {
		peers <- conn.RemoteAddr().String()
		go func() {
			defer conn.Close()
			if _, err := conn.Write([]byte{'!'}); err == nil {
				io.Copy(conn, conn)
			}
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	client := &internet.MemoryStreamConfig{
		ProtocolSettings: &splithttp.Config{Mode: "packet-up", Xmux: &splithttp.XmuxConfig{
			MaxConnections: &splithttp.RangeConfig{From: 1, To: 1},
		}},
		SecuritySettings: &tls.Config{
			ServerName:           "localhost",
			PinnedPeerCertSha256: [][]byte{hash[:]},
			NextProtocol:         []string{"h3"},
		},
		SecurityType: "tls",
	}
	dest := net.UDPDestination(net.LocalHostIP, net.Port(listener.Addr().(*net.UDPAddr).Port))

	readByte := func(conn stat.Connection, want byte, operation string) {
		t.Helper()
		timeout := time.AfterFunc(3*time.Second, func() { conn.Close() })
		var b [1]byte
		_, err := io.ReadFull(conn, b[:])
		if !timeout.Stop() {
			t.Fatalf("%s: timed out", operation)
		}
		if err != nil || b[0] != want {
			t.Fatalf("%s: got %q, want %q, err %v", operation, b[0], want, err)
		}
	}
	open := func() stat.Connection {
		t.Helper()
		conn, err := splithttp.Dial(t.Context(), dest, client)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		// The greeting confirms that the server has accepted the download stream.
		readByte(conn, '!', "open session")
		return conn
	}
	echo := func(conn stat.Connection, b byte, operation string) {
		t.Helper()
		if _, err := conn.Write([]byte{b}); err != nil {
			t.Fatal(err)
		}
		readByte(conn, b, operation)
	}

	first := open()
	firstPeer := <-peers
	echo(first, 'a', "first session before second download")
	second := open()
	if <-peers != firstPeer {
		t.Fatal("expected both downloads to share a QUIC connection")
	}
	echo(first, 'b', "first session after second download")
	echo(second, 'c', "second session")
	third := open()
	if <-peers == firstPeer {
		t.Fatal("third download exceeded the configured two-stream limit")
	}
	echo(third, 'd', "third session")
	// Shut down with both the draining and the replacement connection still in use.
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
