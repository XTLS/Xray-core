package websocket_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
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

// A reader waits for the next message outside the connection, where it holds no buffer,
// whatever the size of the last one: one of full buffers looked like one that goes on.
func Test_listenWS_WaitsAfterMessage(t *testing.T) {
	listenPort := tcp.PickPort()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
	}
	waited := make(chan time.Duration, 1)
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			io.ReadFull(conn, make([]byte, buf.Size))
			start := time.Now()
			conn.(interface{ WaitRead() }).WaitRead()
			waited <- time.Since(start)
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	defer conn.Close()
	common.Must2(conn.Write(make([]byte, buf.Size)))
	time.Sleep(200 * time.Millisecond)
	common.Must2(conn.Write([]byte{1}))
	if d := <-waited; d < 100*time.Millisecond {
		t.Error("the reader waited for ", d)
	}
}

// The reader of the server gets its early data, then frames that came in one segment: the second one
// is buffered when the reader looks for more, and nothing else comes to end a wait.
func Test_listenWS_FramesInOneSegment(t *testing.T) {
	listenPort := tcp.PickPort()
	copied := make(chan error, 1)
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
	}, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			copied <- buf.Copy(buf.NewReader(conn), buf.NewWriter(conn))
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := net.Dial("tcp", net.TCPDestination(net.LocalHostIP, listenPort).NetAddr())
	common.Must(err)
	defer conn.Close()
	start := time.Now()
	common.Must(conn.SetDeadline(start.Add(2 * time.Second)))
	common.Must2(conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: " + base64.RawURLEncoding.EncodeToString([]byte("xyz")) + "\r\n\r\n")))
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	common.Must(err)
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatal("status: ", response.Status)
	}
	echo := func(frames []byte) {
		b := make([]byte, len(frames))
		if _, err := io.ReadFull(reader, b); err != nil || !bytes.Equal(b, frames) {
			t.Fatal("read: ", b, ", error: ", err, ", after: ", time.Since(start))
		}
	}
	echo([]byte{0x82, 3, 'x', 'y', 'z'})
	// two binary frames in one segment, masked with zeros, and then nothing
	common.Must2(conn.Write([]byte{0x82, 0x83, 0, 0, 0, 0, 'a', 'b', 'c', 0x82, 0x82, 0, 0, 0, 0, 'd', 'e'}))
	echo([]byte{0x82, 3, 'a', 'b', 'c', 0x82, 2, 'd', 'e'})
	// a reset that ends the wait of the reader is what its read fails with, it is not read away
	time.Sleep(50 * time.Millisecond)
	common.Must(conn.(*net.TCPConn).SetLinger(0))
	conn.Close()
	if err := <-copied; !buf.IsReadError(err) || !errors.As(err, new(*gonet.OpError)) {
		t.Error("copy: ", err)
	}
}
