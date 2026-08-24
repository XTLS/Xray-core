package httpupgrade_test

import (
	"context"
	"runtime"
	"strings"
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
	for _, test := range []struct {
		name       string
		mode       string
		want       string
		wantPrefix string
	}{
		{name: "legacy X-Forwarded-For", want: "1.1.1.1:0"},
		{name: "dedicated direct listener keeps X-Forwarded-For", mode: "dedicated-direct", want: "1.1.1.1:0"},
		{name: "same-port source-aware listener ignores X-Forwarded-For", mode: "same-port", wantPrefix: "127.0.0.1:"},
	} {
		t.Run(test.name, func(t *testing.T) {
			listenPort := tcp.PickPort()
			socketSettings := &internet.SocketConfig{TrustedXForwardedFor: []string{"X-Forwarded-For"}}
			if test.mode != "" {
				socketSettings.ProxyProtocolMode = internet.SocketConfig_ProxyProtocolTrustedSources
				socketSettings.ProxyProtocolTrustedSources = []string{"192.0.2.10"}
				if test.mode == "dedicated-direct" {
					proxyPort := tcp.PickPort()
					for proxyPort == listenPort {
						proxyPort = tcp.PickPort()
					}
					socketSettings.ProxyProtocolListenPorts = []uint32{uint32(proxyPort)}
				}
			}
			listen, err := ListenHTTPUpgrade(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
				ProtocolName:     "httpupgrade",
				ProtocolSettings: &Config{Path: "httpupgrade"},
				SocketSettings:   socketSettings,
			}, func(conn stat.Connection) {
				go func(c stat.Connection) {
					defer c.Close()
					var b [1024]byte
					if _, err := c.Read(b[:]); err == nil {
						_, _ = c.Write([]byte(c.RemoteAddr().String()))
					}
				}(conn)
			})
			common.Must(err)
			defer listen.Close()

			conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
				ProtocolName:     "httpupgrade",
				ProtocolSettings: &Config{Path: "httpupgrade", Header: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
			})
			common.Must(err)
			defer conn.Close()
			_, err = conn.Write([]byte("Test connection 1"))
			common.Must(err)

			var b [1024]byte
			n, err := conn.Read(b[:])
			common.Must(err)
			got := string(b[:n])
			if test.want != "" && got != test.want {
				t.Fatalf("response = %q, want %q", got, test.want)
			}
			if test.wantPrefix != "" && !strings.HasPrefix(got, test.wantPrefix) {
				t.Fatalf("response = %q, want prefix %q", got, test.wantPrefix)
			}
		})
	}
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
