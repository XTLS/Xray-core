package xdrive

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
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

// over TLS a request that stands still ends the same way, and says so, on h2
// as on h1
func TestServiceClientStallOverTLS(t *testing.T) {
	const stall = 200 * time.Millisecond
	for _, protos := range [][]string{chromeALPN, {"http/1.1"}} {
		server := newTLSServer(t, &gotls.Config{NextProtos: protos}, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/stuck" {
				w.Write([]byte("x"))
				w.(http.Flusher).Flush()
			}
			time.Sleep(5 * stall)
		})
		client := newServiceClient(server.settings(&tls.Config{}), stall, 8)

		for _, path := range []string{"/stuck", "/silent"} {
			start := time.Now()
			resp, err := client.Get(server.URL + path)
			if err == nil {
				if resp.Proto != picked(protos) {
					t.Fatalf("%s went over %s", path, resp.Proto)
				}
				_, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if !errors.Is(err, errStalled) {
				t.Errorf("server %v: %s gave %v, want %v", protos, path, err, errStalled)
			}
			if took := time.Since(start); took > 4*stall {
				t.Errorf("server %v: %s took %v to give up", protos, path, took)
			}
		}
	}
}

// tlsServer is a TLS server that keeps the last hello it got and counts its
// connections
type tlsServer struct {
	*httptest.Server
	mu    sync.Mutex
	hello *gotls.ClientHelloInfo
	conns atomic.Int32
}

func newTLSServer(t *testing.T, config *gotls.Config, handler http.HandlerFunc) *tlsServer {
	t.Helper()

	s := &tlsServer{Server: httptest.NewUnstartedServer(handler)}
	config.GetConfigForClient = func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
		s.mu.Lock()
		s.hello = hello
		s.mu.Unlock()
		return nil, nil
	}
	s.TLS = config
	s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			s.conns.Add(1)
		}
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func (s *tlsServer) lastHello() *gotls.ClientHelloInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hello
}

// settings pins the certificate of the server in config
func (s *tlsServer) settings(config *tls.Config) *internet.MemoryStreamConfig {
	config.PinnedPeerCertSha256 = [][]byte{tls.GenerateCertHash(s.Certificate())}
	return &internet.MemoryStreamConfig{ProtocolName: protocolName, SecuritySettings: config}
}

// picked is the protocol a server with ALPN protos answers a Chrome hello with
func picked(protos []string) string {
	if protos[0] == "h2" {
		return "HTTP/2.0"
	}
	return "HTTP/1.1"
}

var chromeALPN = []string{"h2", "http/1.1"}

// the hello offers the ALPN of the fingerprint whatever "alpn" says, or with Go
// TLS that of the config, h2 and http/1.1 by default, and the client speaks what
// the server picks from it
func TestServiceClientSpeaksWhatServerPicks(t *testing.T) {
	for _, protos := range [][]string{chromeALPN, {"http/1.1"}} {
		server := newTLSServer(t, &gotls.Config{NextProtos: protos}, func(w http.ResponseWriter, r *http.Request) {})
		for _, config := range []*tls.Config{{}, {NextProtocol: []string{"h2"}}, {NextProtocol: []string{"http/1.1"}}, {Fingerprint: "unsafe"}} {
			client := newServiceClient(server.settings(config), 5*time.Second, 8)
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("server %v, alpn %v, fingerprint %q: %v", protos, config.NextProtocol, config.Fingerprint, err)
			}
			resp.Body.Close()
			if resp.Proto != picked(protos) {
				t.Errorf("server %v, alpn %v, fingerprint %q: went over %s", protos, config.NextProtocol, config.Fingerprint, resp.Proto)
			}
			if offered := server.lastHello().SupportedProtos; !slices.Equal(offered, chromeALPN) {
				t.Errorf("server %v, alpn %v, fingerprint %q: the hello offered %v, want %v", protos, config.NextProtocol, config.Fingerprint, offered, chromeALPN)
			}
		}
	}
}

// with no tlsSettings the hello is that of Chrome too, which unlike Go TLS
// offers certificate compression
func TestServiceClientDefaultsToChrome(t *testing.T) {
	server := newTLSServer(t, &gotls.Config{NextProtos: chromeALPN}, func(w http.ResponseWriter, r *http.Request) {})
	client := newServiceClient(&internet.MemoryStreamConfig{}, 5*time.Second, 8)
	// the test certificate is not trusted, the hello is all that is needed
	if resp, err := client.Get(server.URL); err == nil {
		resp.Body.Close()
	}
	hello := server.lastHello()
	if hello == nil {
		t.Fatal("no hello")
	}
	if !slices.Equal(hello.SupportedProtos, chromeALPN) || !slices.Contains(hello.Extensions, 27) {
		t.Errorf("the hello offered %v with extensions %v, not like Chrome", hello.SupportedProtos, hello.Extensions)
	}
}

// parallel requests share one h2 connection instead of dialing one each, the
// first ones as the later ones, and next to a host that answers over h1
func TestServiceClientOneConnection(t *testing.T) {
	server := newTLSServer(t, &gotls.Config{NextProtos: chromeALPN}, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	})
	h1 := newTLSServer(t, &gotls.Config{NextProtos: []string{"http/1.1"}}, func(w http.ResponseWriter, r *http.Request) {})
	client := newServiceClient(server.settings(&tls.Config{}), 5*time.Second, driveMaxInflight)
	get := func(url string) {
		resp, err := client.Get(url)
		if err != nil {
			t.Error(err)
			return
		}
		resp.Body.Close()
	}

	for i := range 2 {
		if i == 1 {
			get(h1.URL)
		}
		var wg sync.WaitGroup
		for range driveMaxInflight {
			wg.Go(func() { get(server.URL) })
		}
		wg.Wait()
		if n := server.conns.Load(); n != 1 {
			t.Errorf("round %d: %d parallel requests took %d connections", i, driveMaxInflight, n)
		}
	}
}

// in the format of xray tls ech, for public name public.example
const (
	testECHConfigList = "AEH+DQA9AAAgACBziE85FLxJySxZAPRHs8CDCbuz1h76I9pLhctC/kgScAAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA=="
	testECHServerKeys = "ACD2AjC5yuBQ3430geNDLdIRndloCry/DBb9ZeYp0TmeowBB/g0APQAAIAAgc4hPORS8ScksWQD0R7PAgwm7s9Ye+iPaS4XLQv5IEnAABAABAAEADnB1YmxpYy5leGFtcGxlAAA="
)

// a server that speaks only h1, or gets ALPN http/1.1 inside ECH or from Go TLS,
// answers over h1, and after that answer parallel requests get more than one
// connection
func TestServiceClientHTTP1(t *testing.T) {
	keys, err := base64.StdEncoding.DecodeString(testECHServerKeys)
	if err != nil {
		t.Fatal(err)
	}
	echKeys, err := tls.ConvertToGoECHKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	ech := &tls.Config{ServerName: "example.com", NextProtocol: []string{"http/1.1"}, EchConfigList: testECHConfigList}

	for _, c := range []struct {
		protos, seen []string
		config       *tls.Config
	}{
		{[]string{"http/1.1"}, chromeALPN, &tls.Config{}},
		{chromeALPN, []string{"http/1.1"}, ech},
		{chromeALPN, []string{"http/1.1"}, &tls.Config{NextProtocol: []string{"http/1.1"}, Fingerprint: "unsafe"}},
	} {
		server := newTLSServer(t, &gotls.Config{NextProtos: c.protos, EncryptedClientHelloKeys: echKeys}, func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
		})
		client := newServiceClient(server.settings(c.config), 5*time.Second, 8)
		get := func() {
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			if resp.Proto != "HTTP/1.1" || resp.TLS.ECHAccepted != (c.config.EchConfigList != "") {
				t.Errorf("server %v, ALPN %v: went over %s, ECH accepted %v", c.protos, c.seen, resp.Proto, resp.TLS.ECHAccepted)
			}
		}

		get()
		first := server.conns.Load()
		var wg sync.WaitGroup
		for range 4 {
			wg.Go(get)
		}
		wg.Wait()
		if offered := server.lastHello().SupportedProtos; !slices.Equal(offered, c.seen) {
			t.Errorf("server %v: saw ALPN %v, want %v", c.protos, offered, c.seen)
		}
		if n := server.conns.Load() - first; n < 2 {
			t.Errorf("server %v, ALPN %v: 4 parallel requests over h1 took %d connections", c.protos, c.seen, n)
		}
	}

	// without the keys the server gets the outer hello, which offers the ALPN of
	// Chrome
	outer := newTLSServer(t, &gotls.Config{NextProtos: chromeALPN}, func(w http.ResponseWriter, r *http.Request) {})
	if resp, err := newServiceClient(outer.settings(ech), 5*time.Second, 8).Get(outer.URL); err == nil {
		resp.Body.Close()
	}
	if hello := outer.lastHello(); hello == nil {
		t.Error("no outer hello")
	} else if !slices.Equal(hello.SupportedProtos, chromeALPN) {
		t.Errorf("the outer hello offered %v, want %v", hello.SupportedProtos, chromeALPN)
	}
}

// muteFirst leaves the first connection it accepts unanswered
type muteFirst struct {
	net.Listener
	muted net.Conn
}

func (l *muteFirst) Accept() (net.Conn, error) {
	if l.muted == nil {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.muted = conn
	}
	return l.Listener.Accept()
}

// a handshake that hangs ends after stall, and does not keep the host from
// getting another connection
func TestServiceClientHungHandshake(t *testing.T) {
	const stall = 200 * time.Millisecond
	for _, fingerprint := range []string{"", "unsafe"} {
		server := &tlsServer{Server: httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))}
		server.Listener = &muteFirst{Listener: server.Listener}
		server.StartTLS()
		t.Cleanup(server.Close)
		client := newServiceClient(server.settings(&tls.Config{Fingerprint: fingerprint}), stall, 8)

		if _, err := client.Get(server.URL); err == nil {
			t.Fatalf("fingerprint %q: a request got through a handshake that hung", fingerprint)
		}
		for i := range 2 {
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("fingerprint %q: request %d after a handshake that hung: %v", fingerprint, i, err)
			}
			resp.Body.Close()
		}
	}
}

// a connection whose handshake failed is closed, not left to the garbage
// collector
func TestServiceClientClosesFailedHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	for _, fingerprint := range []string{"", "unsafe"} {
		settings := &internet.MemoryStreamConfig{ProtocolName: protocolName, SecuritySettings: &tls.Config{Fingerprint: fingerprint}}
		go newServiceClient(settings, 5*time.Second, 8).Get("https://" + ln.Addr().String())
		conn, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		// not TLS, so the handshake fails at once
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Errorf("fingerprint %q: the client left the connection open: %v", fingerprint, err)
		}
		conn.Close()
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
