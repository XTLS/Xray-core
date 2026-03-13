package splithttp_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
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

// Acceptance test: measures memory usage during high-throughput XHTTP transfer.
// This test sends 10MB of data through packet-up mode and verifies that
// heap memory does not exceed a reasonable threshold.
func Test_MemoryUsage_PacketUp(t *testing.T) {
	listenPort := tcp.PickPort()

	const totalBytes = 10 * 1024 * 1024 // 10 MB
	const chunkSize = 16 * 1024         // 16 KB writes (typical VPN packet pattern)
	// Before optimizations: ~68MB. After: ~24MB (2.4x data size).
	const maxTotalAlloc = 30 * 1024 * 1024

	streamSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/mem-test",
			ScMaxEachPostBytes: &RangeConfig{
				From: 256000,
				To:   256000,
			},
			ScMaxBufferedPosts: 10,
		},
	}

	var serverReceived int
	var serverMu sync.Mutex
	serverDone := make(chan struct{})

	listen, err := ListenXH(context.Background(), net.LocalHostIP, listenPort, streamSettings, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			readBuf := make([]byte, 32*1024)
			for {
				n, err := c.Read(readBuf)
				if err != nil {
					break
				}
				serverMu.Lock()
				serverReceived += n
				done := serverReceived >= totalBytes
				serverMu.Unlock()
				if done {
					break
				}
			}
			_, _ = c.Write([]byte("OK"))
			close(serverDone)
		}(conn)
	})
	common.Must(err)
	defer listen.Close()

	conn, err := Dial(context.Background(), net.TCPDestination(net.DomainAddress("localhost"), listenPort), streamSettings)
	common.Must(err)
	defer conn.Close()

	// Force GC before measurement
	runtime.GC()
	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	// Send data in realistic chunks
	data := make([]byte, chunkSize)
	_, _ = rand.Read(data)
	bytesSent := 0
	for bytesSent < totalBytes {
		n, err := conn.Write(data)
		if err != nil {
			t.Fatalf("write error after %d bytes: %v", bytesSent, err)
		}
		bytesSent += n
	}

	// Wait for server to receive everything
	select {
	case <-serverDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for server to receive all data")
	}

	runtime.GC()
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	totalAllocDelta := memAfter.TotalAlloc - memBefore.TotalAlloc
	t.Logf("Data transferred: %d bytes", bytesSent)
	t.Logf("Heap before: %d bytes, after: %d bytes, delta: %d bytes",
		memBefore.HeapInuse, memAfter.HeapInuse, memAfter.HeapInuse-memBefore.HeapInuse)
	t.Logf("TotalAlloc delta: %d bytes", totalAllocDelta)
	t.Logf("Mallocs delta: %d", memAfter.Mallocs-memBefore.Mallocs)

	if totalAllocDelta > maxTotalAlloc {
		t.Errorf("Total allocations too high: %d bytes (threshold %d bytes). "+
			"Memory optimization needed.", totalAllocDelta, maxTotalAlloc)
	}

	serverMu.Lock()
	if serverReceived < totalBytes {
		t.Errorf("Server received only %d/%d bytes", serverReceived, totalBytes)
	}
	serverMu.Unlock()
}

// Benchmark allocation count for upload queue push/read cycle
func BenchmarkUploadQueue_PushRead(b *testing.B) {
	data := make([]byte, 1400) // typical MTU-sized packet
	_, _ = rand.Read(data)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		q := NewUploadQueue(30)
		_ = q.Push(Packet{
			Payload: data,
			Seq:     0,
		})
		readBuf := make([]byte, 1400)
		_, _ = q.Read(readBuf)
		q.Close()
	}
}
