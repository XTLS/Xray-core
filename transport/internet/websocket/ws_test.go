package websocket_test

import (
	"context"
	"errors"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	. "github.com/xtls/xray-core/transport/internet/websocket"
)

func Test_listenWSAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "websocket",
		ProtocolSettings: &Config{
			Path: "ws",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)

	ctx := context.Background()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, err = conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "websocket",
		ProtocolSettings: &Config{
			Path: "ws",
		},
		SocketSettings: &internet.SocketConfig{
			TrustedXForwardedFor: []string{"X-Forwarded-For"},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [1024]byte
			_, err := c.Read(b[:])
			// common.Must(err)
			if err != nil {
				return
			}

			_, err = c.Write([]byte(c.RemoteAddr().String()))
			common.Must(err)
		}(conn)
	})
	common.Must(err)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, err := conn.Read(b[:])
	common.Must(err)
	if string(b[:n]) != "1.1.1.1:0" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(listen.Close())
}

func Test_listenWSAndDial_TLS(t *testing.T) {
	listenPort := tcp.PickPort()
	if runtime.GOARCH == "arm64" {
		return
	}

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "websocket",
		ProtocolSettings: &Config{
			Path: "wss",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			_ = conn.Close()
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	_ = conn.Close()

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}

func TestDialClosesConnOnUTLSHandshakeFailure(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer l.Close()
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
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					err = nil
				}
				result <- err
				return
			}
		}
	}()

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "wss"},
		SecurityType:     "tls",
		SecuritySettings: &tls.Config{ServerName: "example.com", Fingerprint: "chrome"},
	}
	if _, err := Dial(context.Background(), net.DestinationFromAddr(l.Addr()), streamSettings); err == nil {
		t.Fatal("expected handshake error")
	}
	if err := <-result; err != nil {
		t.Fatal("client did not close the connection:", err)
	}
}
