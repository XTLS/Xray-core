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

func Test_ListenXHAndDial_PacketDown(t *testing.T) {
	packetDown := &PacketDownConfig{
		KeepAlive:       true,
		KeepAlivePeriod: &RangeConfig{From: 2, To: 2},
		KeepAliveLength: &RangeConfig{From: 24, To: 64},
	}

	payload := make([]byte, 100*1024)
	rand.Read(payload)

	listenPort := tcp.PickPort()
	serverStreamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path:       "/sh",
			PacketDown: packetDown,
		},
	}
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, serverStreamSettings, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [32]byte
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			written := 0
			for written < len(payload) {
				step := 8192
				if written+step > len(payload) {
					step = len(payload) - written
				}
				if _, err := c.Write(payload[written : written+step]); err != nil {
					return
				}
				written += step
			}
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	ctx := context.Background()
	clientStreamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path:       "sh",
			PacketDown: packetDown,
		},
	}
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), clientStreamSettings)
	common.Must(err)

	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Error("100 KiB came back different through packet-down")
	}

	common.Must(conn.Close())
}

func Test_ListenXHAndDial_PacketDownWithoutServer(t *testing.T) {
	// client asks, server has no packetDown: the response is still raw
	listenPort := tcp.PickPort()
	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/sh",
		},
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()

			var b [32]byte
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := c.Read(b[:])
			if err != nil {
				return
			}

			common.Must2(c.Write([]byte("Response")))
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	ctx := context.Background()
	conn, err := Dial(ctx, net.TCPDestination(net.DomainAddress("localhost"), listenPort), &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path:       "sh",
			PacketDown: &PacketDownConfig{KeepAlive: true},
		},
	})
	common.Must(err)

	_, err = conn.Write([]byte("Test connection 1"))
	common.Must(err)

	var b [1024]byte
	n, _ := io.ReadFull(conn, b[:])
	if string(b[:n]) != "Response" {
		t.Error("response: ", string(b[:n]))
	}

	common.Must(conn.Close())
}
