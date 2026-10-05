package httpupgrade_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Test_listenHTTPUpgradeAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
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
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
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

func Test_listenHTTPUpgradeAndDialWithHeaders(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
			Header: map[string]string{
				"User-Agent": "Mozilla",
			},
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
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
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
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrade",
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
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
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

func Test_listenHTTPUpgradeAndDial_TLS(t *testing.T) {
	listenPort := tcp.PickPort()
	if runtime.GOARCH == "arm64" {
		return
	}

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &Config{
			Path: "httpupgrades",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
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

func TestDial_ReadPastResponse(t *testing.T) {
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listen.Close()
	go func() {
		conn, err := listen.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		// the last 13 bytes of the response and what follows it are what the client reads at once
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nabc"))
		io.Copy(conn, conn)
	}()

	conn, err := Dial(context.Background(), net.TCPDestination(net.LocalHostIP, net.Port(listen.Addr().(*net.TCPAddr).Port)), &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade", Ed: 2048},
	})
	common.Must(err)
	defer conn.Close()

	common.Must(conn.SetReadDeadline(time.Now().Add(4 * time.Second)))
	// as the version of a VLESS response is read
	b := make([]byte, 1)
	read := func(expected string) {
		for i := range expected {
			if n, err := conn.Read(b); n != 1 || err != nil || b[0] != expected[i] {
				t.Fatal("read: ", n, " ", err, " ", string(b[:n]), ", expected: ", expected[i:i+1])
			}
		}
	}
	read("abc")
	common.Must2(conn.Write([]byte("def")))
	read("def")
}

func TestListen_ReadPastRequest(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName:     "httpupgrade",
		ProtocolSettings: &Config{Path: "httpupgrade"},
	}, func(conn stat.Connection) {
		go func() {
			defer conn.Close()
			io.Copy(conn, conn)
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := net.Dial("tcp", net.TCPDestination(net.LocalHostIP, listenPort).NetAddr())
	common.Must(err)
	defer conn.Close()
	// as a client with early data may send them: the request and what follows it in one segment
	common.Must2(conn.Write([]byte("GET /httpupgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nabc")))
	common.Must(conn.SetReadDeadline(time.Now().Add(4 * time.Second)))
	reader := bufio.NewReader(conn)
	_, err = http.ReadResponse(reader, nil) // nolint:bodyclose
	common.Must(err)
	b := make([]byte, 6)
	common.Must2(conn.Write([]byte("def")))
	if _, err := io.ReadFull(reader, b); err != nil || string(b) != "abcdef" {
		t.Fatal("read: ", string(b), " ", err)
	}
}
