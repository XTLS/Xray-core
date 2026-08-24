package websocket_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	. "github.com/xtls/xray-core/transport/internet/websocket"
)

func TestSourceAwareProxyAddressOverridesXForwardedFor(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenWS(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws"},
		SocketSettings: &internet.SocketConfig{
			ProxyProtocolMode:           internet.SocketConfig_ProxyProtocolTrustedSources,
			ProxyProtocolTrustedSources: []string{"127.0.0.1"},
			ProxyProtocolListenPorts:    []uint32{uint32(listenPort)},
			TrustedXForwardedFor:        []string{"X-Forwarded-For"},
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			var b [1024]byte
			if _, err := c.Read(b[:]); err == nil {
				_, _ = c.Write([]byte(c.RemoteAddr().String()))
			}
		}(conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listen.Close() })

	header, err := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 12345},
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(listenPort)},
	).Format()
	if err != nil {
		t.Fatal(err)
	}
	forwardPort := startProxyProtocolV2Forwarder(t, listenPort, header)

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), forwardPort), &internet.MemoryStreamConfig{
		ProtocolName:     "websocket",
		ProtocolSettings: &Config{Path: "ws", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("source-aware XFF precedence")); err != nil {
		t.Fatal(err)
	}

	var b [128]byte
	n, err := conn.Read(b[:])
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b[:n]); got != "203.0.113.7:12345" {
		t.Fatalf("remote address = %q, want validated PROXY address", got)
	}
}

func startProxyProtocolV2Forwarder(t *testing.T, targetPort net.Port, prefix []byte) net.Port {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			downstream, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer downstream.Close()
				upstream, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", targetPort.String()))
				if err != nil {
					return
				}
				defer upstream.Close()
				_ = downstream.SetDeadline(time.Now().Add(10 * time.Second))
				_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := upstream.Write(prefix); err != nil {
					return
				}
				copyDone := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, downstream)
					close(copyDone)
				}()
				_, _ = io.Copy(downstream, upstream)
				<-copyDone
			}()
		}
	}()

	return net.Port(listener.Addr().(*net.TCPAddr).Port)
}
