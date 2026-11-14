package splithttp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/testing/servers/udp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func Test_ListenXHAndDial(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/sh",
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
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "sh"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	fmt.Println("test2")
	n, _ := io.ReadFull(conn, b[:])
	fmt.Println("string is", n)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, _ = io.ReadFull(conn, b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func TestDialWithRemoteAddr(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "sh",
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
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "sh", Headers: map[string]string{"X-Forwarded-For": "1.1.1.1"}},
	})

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, _ := io.ReadFull(conn, b[:])
	if string(b[:n]) != "1.1.1.1:0" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(listen.Close())
}

func Test_ListenXHAndDial_TLS(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		return
	}

	listenPort := tcp.PickPort()

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "shs",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
		},
	}
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()

			var b [1024]byte
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err := conn.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(conn.Write([]byte("Response")))
		}()
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)

	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, _ := io.ReadFull(conn, b[:])
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}

func Test_ListenXHAndDial_H2C(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		return
	}

	listenPort := tcp.PickPort()

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "shs",
		},
	}
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			_ = conn.Close()
		}()
	})
	common.Must(err)
	defer listen.Close()

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			Protocols: protocols,
		},
	}

	resp, err := client.Get("http://" + net.LocalHostIP.String() + ":" + listenPort.String())
	common.Must(err)

	if resp.StatusCode != 404 {
		t.Error("Expected 404 but got:", resp.StatusCode)
	}

	if resp.ProtoMajor != 2 {
		t.Error("Expected h2 but got:", resp.ProtoMajor)
	}
}

func Test_ListenXHAndDial_QUIC(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		return
	}

	listenPort := udp.PickPort()

	start := time.Now()

	ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "shs",
		},
		SecurityType: "tls",
		SecuritySettings: &tls.Config{
			Certificate:          []*tls.Certificate{tls.ParseCertificate(ct)},
			PinnedPeerCertSha256: [][]byte{ctHash[:]},
			NextProtocol:         []string{"h3"},
		},
	}

	serverClosed := false
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func() {
			defer conn.Close()

			b := buf.New()
			defer b.Release()

			for {
				b.Clear()
				if _, err := b.ReadFrom(conn); err != nil {
					break
				}
				common.Must2(conn.Write(b.Bytes()))
			}

			serverClosed = true
		}()
	})
	common.Must(err)
	defer listen.Close()

	time.Sleep(time.Second)

	conn, err := Dial(context.Background(), net.UDPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)

	const N = 1024
	b1 := make([]byte, N)
	common.Must2(rand.Read(b1))
	b2 := buf.New()

	common.Must2(conn.Write(b1))

	b2.Clear()
	common.Must2(b2.ReadFullFrom(conn, N))
	if r := cmp.Diff(b2.Bytes(), b1); r != "" {
		t.Error(r)
	}

	common.Must2(conn.Write(b1))

	b2.Clear()
	common.Must2(b2.ReadFullFrom(conn, N))
	if r := cmp.Diff(b2.Bytes(), b1); r != "" {
		t.Error(r)
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)
	if !serverClosed {
		t.Error("server did not get closed")
	}

	end := time.Now()
	if !end.Before(start.Add(time.Second * 5)) {
		t.Error("end: ", end, " start: ", start)
	}
}

func Test_ListenXHAndDial_Unix(t *testing.T) {
	tempDir := t.TempDir()
	tempSocket := tempDir + "/server.sock"

	listen, err := ListenXH(context.Background(), net.DomainAddress(tempSocket), 0, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/sh",
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
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Host: "example.com",
			Path: "sh",
		},
	}
	conn, err := Dial(ctx, net.UnixDestination(net.DomainAddress(tempSocket)), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	fmt.Println("test2")
	n, _ := io.ReadFull(conn, b[:])
	fmt.Println("string is", n)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	conn, err = Dial(ctx, net.UnixDestination(net.DomainAddress(tempSocket)), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 2"))
	common.Must(err)
	n, _ = io.ReadFull(conn, b[:])
	common.Must(err)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	common.Must(listen.Close())
}

func Test_queryString(t *testing.T) {
	listenPort := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			// this querystring does not have any effect, but sometimes people blindly copy it from websocket config. make sure the outbound doesn't break
			Path: "/sh?ed=2048",
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
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "sh?ed=2048"},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)

	common.Must(err)
	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	fmt.Println("test2")
	n, _ := io.ReadFull(conn, b[:])
	fmt.Println("string is", n)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
	common.Must(listen.Close())
}

func Test_maxUpload(t *testing.T) {
	listenPort := tcp.PickPort()
	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/sh",
			ScMaxEachPostBytes: &RangeConfig{
				From: 10000,
				To:   10000,
			},
		},
	}

	uploadReceived := make([]byte, 10001)
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadFull(c, uploadReceived)

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)
	ctx := context.Background()

	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)

	// send a slightly too large upload
	upload := make([]byte, 10001)
	rand.Read(upload)
	_, err = conn.Write(upload)
	common.Must(err)

	var b [10240]byte
	n, _ := io.ReadFull(conn, b[:])
	fmt.Println("string is", n)
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}
	common.Must(conn.Close())

	if !bytes.Equal(upload, uploadReceived) {
		t.Error("incorrect upload", upload, uploadReceived)
	}

	common.Must(listen.Close())
}

func newPacketUpEchoServer(t *testing.T, serverCfg *Config) net.Port {
	t.Helper()
	port := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: serverCfg,
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			var b [5]byte
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, b[:]); err != nil {
				return
			}
			common.Must2(c.Write(append([]byte("echo:"), b[:]...)))
		}(conn)
	})
	common.Must(err)
	t.Cleanup(func() { listen.Close() })
	return port
}

// uplinkEcho fails instead of hanging when the uplink never reaches the server.
func uplinkEcho(t *testing.T, mode, method, transport string) error {
	t.Helper()
	res := make(chan error, 1)
	go func() { res <- uplinkEchoOnce(mode, method, transport) }()
	select {
	case err := <-res:
		return err
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timed out")
	}
}

func uplinkEchoOnce(mode, method, transport string) error {
	port := tcp.PickPort()
	serverCfg := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "/sh", Mode: mode},
	}
	clientCfg := &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: &Config{Path: "/sh", Mode: mode, UplinkHTTPMethod: method},
	}
	if transport == "tls" {
		ct, ctHash := cert.MustGenerate(nil, cert.CommonName("localhost"))
		sec := &tls.Config{Certificate: []*tls.Certificate{tls.ParseCertificate(ct)}, PinnedPeerCertSha256: [][]byte{ctHash[:]}}
		serverCfg.SecurityType, serverCfg.SecuritySettings = "tls", sec
		clientCfg.SecurityType, clientCfg.SecuritySettings = "tls", sec
	}
	listen, err := ListenXH(context.Background(), net.LocalHostIP, port, serverCfg, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			var b [5]byte
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, b[:]); err != nil {
				return
			}
			common.Must2(c.Write(append([]byte("echo:"), b[:]...)))
		}(conn)
	})
	if err != nil {
		return err
	}
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), port), clientCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("hello")); err != nil {
		return err
	}
	var b [1024]byte
	conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	n, err := io.ReadFull(conn, b[:len("echo:hello")])
	if err != nil || string(b[:n]) != "echo:hello" {
		return fmt.Errorf("got %q: %v", b[:n], err)
	}
	return nil
}

// OPTIONS must carry uplink data exactly like POST does, in every mode and over every transport.
func Test_UplinkHTTPMethodOptions(t *testing.T) {
	for _, transport := range []string{"plain", "tls"} {
		for _, mode := range []string{"packet-up", "stream-up", "stream-one", "auto"} {
			t.Run(transport+"/"+mode, func(t *testing.T) {
				if transport == "tls" && runtime.GOARCH == "arm64" {
					t.Skip("TLS tests are skipped on arm64, like the other TLS tests in this package")
				}
				if err := uplinkEcho(t, mode, "POST", transport); err != nil {
					t.Skipf("POST baseline does not work in this setup: %v", err)
				}
				for _, method := range []string{"PUT", "OPTIONS"} {
					if err := uplinkEcho(t, mode, method, transport); err != nil {
						t.Errorf("%s: %v", method, err)
					}
				}
			})
		}
	}
}

func Test_CORSPreflightStillAnswered(t *testing.T) {
	port := newPacketUpEchoServer(t, &Config{Path: "/sh", Mode: "packet-up"})
	req, _ := http.NewRequest("OPTIONS", fmt.Sprintf("http://127.0.0.1:%d/sh/", port), nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	common.Must(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preflight status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "POST" {
		t.Errorf("Allow-Methods = %q", got)
	}
}

func Test_ServerMaxHeaderBytes(t *testing.T) {
	port := newPacketUpEchoServer(t, &Config{Path: "/sh", Mode: "packet-up", ServerMaxHeaderBytes: 2048})
	big := bytes.Repeat([]byte("a"), 8192)
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/sh/", port), nil)
	req.Header.Set("X-Big", string(big))
	resp, err := http.DefaultClient.Do(req)
	common.Must(err)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header status = %d, want 431", resp.StatusCode)
	}
}
