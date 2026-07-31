package splithttp_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// startIdleCutProxy is a stand-in for a fronting CDN / reverse proxy with a
// response idle-read timeout (nginx proxy_read_timeout, Cloudflare edge, ...).
// It forwards bytes both ways, but if the upstream (the XHTTP server) sends
// nothing for `idle`, it tears the connection down -- exactly what kills a
// silent stream-down half during a bulk upload.
func startIdleCutProxy(t *testing.T, upstream string, idle time.Duration) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				up, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer up.Close()
				// client -> upstream: plain copy (uploads).
				go io.Copy(up, client)
				// upstream -> client: copy, but cut on read idle.
				buf := make([]byte, 32*1024)
				for {
					up.SetReadDeadline(time.Now().Add(idle))
					n, err := up.Read(buf)
					if n > 0 {
						if _, werr := client.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return // idle timeout (or real EOF) -> cut
					}
				}
			}(client)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// readWithTimeout reads once with a wall-clock deadline, since splitConn's
// SetReadDeadline is a no-op.
func readWithTimeout(conn stat.Connection, want int, d time.Duration) ([]byte, error) {
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 64)
		for got.Len() < want {
			n, err := conn.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				ch <- res{got.Bytes(), err}
				return
			}
		}
		ch <- res{got.Bytes(), nil}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(d):
		return nil, context.DeadlineExceeded
	}
}

// serverConfig builds a plaintext (h1/h2c) splithttp server config. When
// downSecs > 0 the server offers stream-down keepalive.
func serverConfig(downSecs int32) *Config {
	c := &Config{
		Path: "/ka",
		Mode: "packet-up",
	}
	if downSecs > 0 {
		c.ScStreamDownServerSecs = &RangeConfig{From: downSecs, To: downSecs}
	}
	return c
}

// listenWithSilentDownlink starts a server whose application handler keeps the
// download half silent for quietFor, then sends `payload`. This models a
// session whose data is flowing upward while the download half is idle.
func listenWithSilentDownlink(t *testing.T, cfg *Config, quietFor time.Duration, payload []byte) (xnet.Port, internet.Listener) {
	t.Helper()
	port := tcp.PickPort()
	ln, err := ListenXH(context.Background(), xnet.LocalHostIP, port, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: cfg,
	}, func(conn stat.Connection) {
		go func(c stat.Connection) {
			defer c.Close()
			time.Sleep(quietFor)
			c.Write(payload)
			time.Sleep(200 * time.Millisecond)
		}(conn)
	})
	common.Must(err)
	return port, ln
}

func dialThroughProxy(t *testing.T, proxyAddr string, clientCfg *Config) (stat.Connection, error) {
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	p, _ := net.LookupPort("tcp", portStr)
	dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(p))
	return Dial(context.Background(), dest, &internet.MemoryStreamConfig{
		ProtocolName:     "splithttp",
		ProtocolSettings: clientCfg,
	})
}

// Test_XHTTP_StreamDownKeepalive_Repro is the core evidence for this PR.
//
// A silent stream-down half behind an idle-cutting proxy is torn down on the
// unpatched server (no keepalive) and survives on the patched one. Run it on
// current main and the "keepalive" subtest fails: the download stalls. Run it
// with this PR and it passes.
func Test_XHTTP_StreamDownKeepalive_Repro(t *testing.T) {
	const (
		idleCut  = 1500 * time.Millisecond
		quietFor = 3 * time.Second // > several idle windows
		downSecs = int32(1)        // keepalive every ~1s < idleCut
	)
	payload := []byte("DOWNLINK-OK")

	t.Run("no-keepalive/stalls", func(t *testing.T) {
		// Server does NOT offer keepalive (old server). Client asks for framing;
		// with no confirmation it reads the raw stream. The silent download is
		// cut before the payload arrives.
		port, ln := listenWithSilentDownlink(t, serverConfig(0), quietFor, payload)
		defer ln.Close()
		proxyAddr, closeProxy := startIdleCutProxy(t, xnet.LocalHostIP.String()+":"+port.String(), idleCut)
		defer closeProxy()

		conn, err := dialThroughProxy(t, proxyAddr, &Config{Path: "/ka", Mode: "packet-up", DownFrame: true})
		common.Must(err)
		defer conn.Close()

		got, err := readWithTimeout(conn, len(payload), quietFor+2*time.Second)
		if err == nil && bytes.Equal(got, payload) {
			t.Fatalf("expected the silent download to be cut without keepalive, but it delivered %q", got)
		}
		t.Logf("download cut as expected (err=%v, got=%q)", err, got)
	})

	t.Run("keepalive/survives", func(t *testing.T) {
		// Server offers keepalive and client opts in -> framing negotiated ->
		// padding records keep the download half alive past the idle cut.
		port, ln := listenWithSilentDownlink(t, serverConfig(downSecs), quietFor, payload)
		defer ln.Close()
		proxyAddr, closeProxy := startIdleCutProxy(t, xnet.LocalHostIP.String()+":"+port.String(), idleCut)
		defer closeProxy()

		conn, err := dialThroughProxy(t, proxyAddr, &Config{Path: "/ka", Mode: "packet-up", DownFrame: true})
		common.Must(err)
		defer conn.Close()

		got, err := readWithTimeout(conn, len(payload), quietFor+2*time.Second)
		if err != nil {
			t.Fatalf("download stalled despite keepalive: err=%v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch through framer: got %q want %q", got, payload)
		}
	})
}

// Test_XHTTP_StreamDownFraming_Compat checks the four cells of the
// old/new client x old/new server matrix. In every cell the application bytes
// must arrive intact: framing is on the wire only when BOTH peers opted in, so
// no single-sided upgrade can corrupt the tunnel.
func Test_XHTTP_StreamDownFraming_Compat(t *testing.T) {
	payload := bytes.Repeat([]byte("The quick brown fox. "), 200) // ~4 KiB

	cells := []struct {
		name        string
		serverKA    bool
		clientFrame bool
	}{
		{"oldClient_oldServer", false, false},
		{"oldClient_newServer", true, false},
		{"newClient_oldServer", false, true},
		{"newClient_newServer", true, true},
	}

	for _, cell := range cells {
		cell := cell
		t.Run(cell.name, func(t *testing.T) {
			var downSecs int32
			if cell.serverKA {
				downSecs = 1
			}
			// No proxy, no artificial quiet period: just verify the bytes.
			port, ln := listenWithSilentDownlink(t, serverConfig(downSecs), 50*time.Millisecond, payload)
			defer ln.Close()

			dest := xnet.TCPDestination(xnet.DomainAddress("localhost"), port)
			conn, err := Dial(context.Background(), dest, &internet.MemoryStreamConfig{
				ProtocolName:     "splithttp",
				ProtocolSettings: &Config{Path: "/ka", Mode: "packet-up", DownFrame: cell.clientFrame},
			})
			common.Must(err)
			defer conn.Close()

			got, err := readWithTimeout(conn, len(payload), 5*time.Second)
			if err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload corrupted in cell %s: got %d bytes, want %d", cell.name, len(got), len(payload))
			}
		})
	}
}
