package splithttp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"github.com/xtls/xray-core/transport/internet"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestResponsePreludeEndToEndThroughBufferingProxy(t *testing.T) {
	backendPort := tcp.PickPort()
	proxyPort := tcp.PickPort()

	responsePrelude := &ResponsePreludeConfig{
		Placement: PlacementCookie,
		Key:       "sample_id",
		Table:     PredefinedTable["Base62"],
		Length:    &RangeConfig{From: 16, To: 32},
	}

	// Application payload is deliberately blocked until the intermediary
	// has observed the response prelude. Without the prelude this creates
	// the same headers-only buffering deadlock seen with some CDNs.
	preludeSeen := make(chan struct{})
	var preludeSeenOnce sync.Once

	backendSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path:            "/sh",
			Mode:            "packet-up",
			ResponsePrelude: responsePrelude,
		},
	}

	listen, err := ListenXH(
		context.Background(),
		xraynet.LocalHostIP,
		backendPort,
		backendSettings,
		func(conn stat.Connection) {
			go func(c stat.Connection) {
				defer c.Close()

				select {
				case <-preludeSeen:
				case <-time.After(2 * time.Second):
					return
				}

				common.Must2(c.Write([]byte("PAYLOAD")))
			}(conn)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	target, err := url.Parse("http://127.0.0.1:" + backendPort.String())
	if err != nil {
		t.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		cookie, err := resp.Request.Cookie("sample_id")
		if err != nil {
			return fmt.Errorf("stream-down request has no sample_id cookie: %w", err)
		}
		if cookie.Value == "" {
			return fmt.Errorf("empty sample_id")
		}

		first := make([]byte, len(cookie.Value))
		if _, err := io.ReadFull(resp.Body, first); err != nil {
			return fmt.Errorf("failed to read initial response bytes: %w", err)
		}
		if !bytes.Equal(first, []byte(cookie.Value)) {
			return fmt.Errorf("first response bytes %q do not match response prelude %q", first, cookie.Value)
		}

		// Replay the bytes so the real XHTTP client receives them and proves
		// that its responsePrelude reader strips them before exposing payload.
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(first), resp.Body))
		preludeSeenOnce.Do(func() { close(preludeSeen) })
		return nil
	}

	proxyListener, err := stdnet.Listen("tcp", "127.0.0.1:"+proxyPort.String())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := &http.Server{Handler: proxy}
	go func() {
		_ = proxyServer.Serve(proxyListener)
	}()
	defer proxyServer.Close()

	clientSettings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path:            "/sh",
			Mode:            "packet-up",
			ResponsePrelude: responsePrelude,
		},
	}

	conn, err := Dial(
		context.Background(),
		xraynet.TCPDestination(xraynet.DomainAddress("localhost"), proxyPort),
		clientSettings,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make([]byte, len("PAYLOAD"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "PAYLOAD" {
		t.Fatalf("upper layer received %q, want PAYLOAD", got)
	}

	select {
	case <-preludeSeen:
	default:
		t.Fatal("intermediary never observed response prelude")
	}
}

func TestResponsePreludeDisabledPreservesLegacyEndToEnd(t *testing.T) {
	listenPort := tcp.PickPort()

	settings := &internet.MemoryStreamConfig{
		ProtocolName: "splithttp",
		ProtocolSettings: &Config{
			Path: "/sh",
			Mode: "packet-up",
		},
	}

	listen, err := ListenXH(
		context.Background(),
		xraynet.LocalHostIP,
		listenPort,
		settings,
		func(conn stat.Connection) {
			go func(c stat.Connection) {
				defer c.Close()
				common.Must2(c.Write([]byte("PAYLOAD")))
			}(conn)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer listen.Close()

	conn, err := Dial(
		context.Background(),
		xraynet.TCPDestination(xraynet.DomainAddress("localhost"), listenPort),
		settings,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	got := make([]byte, len("PAYLOAD"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "PAYLOAD" {
		t.Fatalf("legacy upper layer received %q, want PAYLOAD", got)
	}
}
