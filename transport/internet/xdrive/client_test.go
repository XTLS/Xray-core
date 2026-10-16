package xdrive

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func recordingTLSListener(t *testing.T, sni *string, mu *sync.Mutex) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			cfg := &gotls.Config{
				GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
					mu.Lock()
					*sni = hello.ServerName
					mu.Unlock()
					return nil, nil
				},
			}
			tconn := gotls.Server(conn, cfg)
			tconn.HandshakeContext(context.Background())
			tconn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln
}

func sniForSettings(t *testing.T, serverName string) string {
	t.Helper()

	var (
		sni string
		mu  sync.Mutex
	)
	ln := recordingTLSListener(t, &sni, &mu)
	addr := ln.Addr().(*net.TCPAddr)

	settings := &internet.MemoryStreamConfig{
		ProtocolName: protocolName,
		Destination: &xnet.Destination{
			Address: xnet.ParseAddress(addr.IP.String()),
			Port:    xnet.Port(addr.Port),
			Network: xnet.Network_TCP,
		},
		SecuritySettings: &tls.Config{ServerName: serverName},
	}

	prev := driveFilesURL
	driveFilesURL = "https://www.googleapis.com/drive/v3/files"
	defer func() { driveFilesURL = prev }()

	client := newServiceClient(settings, 5*time.Second, 8)
	req, err := http.NewRequest(http.MethodGet, driveFilesURL, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	client.Do(req)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := sni
		mu.Unlock()
		if got != "" {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ""
}

func TestServiceSNIDefaultsToHost(t *testing.T) {
	if got := sniForSettings(t, ""); got != "www.googleapis.com" {
		t.Fatalf("SNI defaulted to %q, want the host www.googleapis.com, not address", got)
	}
}

func TestServiceSNIOverride(t *testing.T) {
	if got := sniForSettings(t, "www.google.com"); got != "www.google.com" {
		t.Fatalf("explicit serverName gave SNI %q, want www.google.com", got)
	}
}

// slowReader hands out one byte every gap, the way a body crosses a slow link
type slowReader struct {
	left int
	gap  time.Duration
}

func (r *slowReader) Read(p []byte) (int, error) {
	if r.left == 0 {
		return 0, io.EOF
	}
	time.Sleep(r.gap)
	r.left--
	p[0] = 'x'
	return 1, nil
}

// a request that keeps moving outlives the stall limit many times over, one
// that stands still does not get much past it
func TestServiceClientEndsOnlyStalledRequests(t *testing.T) {
	const stall = 200 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/slow":
			for i := 0; i < 20; i++ {
				w.Write([]byte("x"))
				w.(http.Flusher).Flush()
				time.Sleep(stall / 4)
			}
		case "/stuck":
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			time.Sleep(5 * stall)
		case "/silent":
			time.Sleep(5 * stall)
		}
	}))
	defer server.Close()
	client := newServiceClient(&internet.MemoryStreamConfig{}, stall, 8)

	fetch := func(path string, body io.Reader) (int, error) {
		req, err := http.NewRequest(http.MethodPost, server.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		got, err := io.ReadAll(resp.Body)
		return len(got), err
	}

	if _, err := fetch("/", &slowReader{left: 20, gap: stall / 4}); err != nil {
		t.Errorf("a slow upload failed: %v", err)
	}
	if n, err := fetch("/slow", nil); err != nil || n != 20 {
		t.Errorf("a slow download gave %d bytes, %v", n, err)
	}
	for _, path := range []string{"/stuck", "/silent"} {
		start := time.Now()
		_, err := fetch(path, nil)
		if !errors.Is(err, errStalled) {
			t.Errorf("%s gave %v, want %v", path, err, errStalled)
		}
		if took := time.Since(start); took > 4*stall {
			t.Errorf("%s took %v to give up", path, took)
		}
	}

	// a body that the transport sends again by itself keeps the request going too
	replay := &serviceTransport{stall: stall, plain: roundTrip(func(r *http.Request) (*http.Response, error) {
		body, err := r.GetBody()
		if err != nil {
			return nil, err
		}
		for b := make([]byte, 1); ; time.Sleep(stall / 4) {
			if _, err := body.Read(b); err != nil {
				break
			}
		}
		if err := context.Cause(r.Context()); err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "http://drive/", bytes.NewReader(make([]byte, 20)))
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := replay.RoundTrip(req); err != nil {
		t.Errorf("a body sent again failed: %v", err)
	} else {
		resp.Body.Close()
	}
}

// over http2 a request that stands still ends the same way, and says so
func TestServiceClientStallOverHTTP2(t *testing.T) {
	const stall = 200 * time.Millisecond
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stuck" {
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
		}
		time.Sleep(5 * stall)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Transport: &serviceTransport{stall: stall, secure: server.Client().Transport}}

	for _, path := range []string{"/stuck", "/silent"} {
		start := time.Now()
		resp, err := client.Get(server.URL + path)
		if err == nil {
			if resp.ProtoMajor != 2 {
				t.Fatalf("%s went over %s", path, resp.Proto)
			}
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if !errors.Is(err, errStalled) {
			t.Errorf("%s gave %v, want %v", path, err, errStalled)
		}
		if took := time.Since(start); took > 4*stall {
			t.Errorf("%s took %v to give up", path, took)
		}
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
