package xdrive

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
	"github.com/xtls/xray-core/transport/internet/splithttp"
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

	client := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8)
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
	client := newServiceClient(context.Background(), new(sync.Map), &internet.MemoryStreamConfig{}, stall, 8)

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
		client := newServiceClient(context.Background(), new(sync.Map), server.settings(&tls.Config{}), stall, 8)

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
// connections, and those closed
type tlsServer struct {
	*httptest.Server
	mu     sync.Mutex
	hello  *gotls.ClientHelloInfo
	conns  atomic.Int32
	closed atomic.Int32
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
		switch state {
		case http.StateNew:
			s.conns.Add(1)
		case http.StateClosed:
			s.closed.Add(1)
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
			client := newServiceClient(context.Background(), new(sync.Map), server.settings(config), 5*time.Second, 8)
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
	client := newServiceClient(context.Background(), new(sync.Map), &internet.MemoryStreamConfig{}, 5*time.Second, 8)
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

// a request says it is chrome, as the hello does, unless it says what it is
func TestServiceClientUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.UserAgent())
	}))
	defer server.Close()
	client := newServiceClient(context.Background(), new(sync.Map), &internet.MemoryStreamConfig{}, 5*time.Second, 8)
	for ua, want := range map[string]string{"": utils.ChromeUA, "firefox": utils.FirefoxUA, "custom/1.0": "custom/1.0"} {
		req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(got) != want {
			t.Errorf("with %q the server got %q, not %q", ua, got, want)
		}
		if req.Header.Get("User-Agent") != ua || len(req.Header) > min(len(ua), 1) {
			t.Errorf("with %q the request was changed to %v", ua, req.Header)
		}
	}
}

// parallel requests share one h2 connection instead of dialing one each, the
// first ones as the later ones, and next to a host that answers over h1
func TestServiceClientOneConnection(t *testing.T) {
	server := newTLSServer(t, &gotls.Config{NextProtos: chromeALPN}, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	})
	h1 := newTLSServer(t, &gotls.Config{NextProtos: []string{"http/1.1"}}, func(w http.ResponseWriter, r *http.Request) {})
	client := newServiceClient(context.Background(), new(sync.Map), server.settings(&tls.Config{}), 5*time.Second, driveMaxInflight)
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
		client := newServiceClient(context.Background(), new(sync.Map), server.settings(c.config), 5*time.Second, 8)
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
	if resp, err := newServiceClient(context.Background(), new(sync.Map), outer.settings(ech), 5*time.Second, 8).Get(outer.URL); err == nil {
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
		client := newServiceClient(context.Background(), new(sync.Map), server.settings(&tls.Config{Fingerprint: fingerprint}), stall, 8)

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
		go newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8).Get("https://" + ln.Addr().String())
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

// afterFuncs counts the functions that context.AfterFunc registers on it and
// that are not stopped yet
type afterFuncs struct {
	context.Context
	live atomic.Int32
}

// Value hides the cancelCtx below, which context.AfterFunc would use instead
func (c *afterFuncs) Value(any) any { return nil }

func (c *afterFuncs) AfterFunc(func()) func() bool {
	c.live.Add(1)
	return func() bool {
		c.live.Add(-1)
		return true
	}
}

// a connection that ends on its own, here after Connection: close, leaves
// nothing on the context that closes the connections of the client
func TestServiceClientForgetsClosedConnections(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	connCtx := &afterFuncs{Context: ctx}
	client := newServiceClient(connCtx, new(sync.Map), &internet.MemoryStreamConfig{}, 5*time.Second, 8)

	for range 4 {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	waitFor(t, "the closed connections to leave the context", func() bool { return connCtx.live.Load() == 0 })
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// "hKeepAlivePeriod" of XMUX sets when an idle h2 connection pings, -1 never,
// and h3 keeps alive only when it is set
func TestServiceClientKeepAlive(t *testing.T) {
	for period, want := range map[int64]time.Duration{0: xnet.ChromeH2KeepAlivePeriod, 20: 20 * time.Second, -1: 0} {
		settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{Xmux: &splithttp.XmuxConfig{HKeepAlivePeriod: period}}}
		client := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8)
		h2 := client.Transport.(*serviceTransport).secure.(*secureTransport).h2.(*http.Transport)
		if got := h2.HTTP2.SendPingTimeout; got != want {
			t.Errorf("hKeepAlivePeriod %d pings after %v, want %v", period, got, want)
		}
	}
	for period, want := range map[int64]time.Duration{0: 0, 20: 20 * time.Second, -1: 0} {
		settings := &internet.MemoryStreamConfig{
			ProtocolSettings: &Config{Xmux: &splithttp.XmuxConfig{HKeepAlivePeriod: period}},
			SecuritySettings: &tls.Config{NextProtocol: []string{"h3"}},
		}
		client := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8)
		if got := client.Transport.(*serviceTransport).secure.(*http3.Transport).QUICConfig.KeepAlivePeriod; got != want {
			t.Errorf("hKeepAlivePeriod %d keeps h3 alive every %v, want %v", period, got, want)
		}
	}
}

// h3 is used when "alpn" asks for it alone, and only then
func TestServiceClientH3Selection(t *testing.T) {
	for _, c := range []struct {
		alpn []string
		h3   bool
	}{
		{nil, false},
		{[]string{"h2"}, false},
		{[]string{"http/1.1"}, false},
		{[]string{"h3", "h2"}, false},
		{[]string{"h2", "h3"}, false},
		{[]string{"h3"}, true},
	} {
		client := newServiceClient(context.Background(), new(sync.Map), &internet.MemoryStreamConfig{SecuritySettings: &tls.Config{NextProtocol: c.alpn}}, 5*time.Second, 8)
		if _, h3 := client.Transport.(*serviceTransport).secure.(*http3.Transport); h3 != c.h3 {
			t.Errorf("alpn %v: h3 %v, want %v", c.alpn, h3, c.h3)
		}
	}
	if _, h3 := newServiceClient(context.Background(), new(sync.Map), &internet.MemoryStreamConfig{}, 5*time.Second, 8).Transport.(*serviceTransport).secure.(*http3.Transport); h3 {
		t.Error("h3 without tlsSettings")
	}
}

// h3Server is an http3 server that keeps the SNI of each connection, and counts
// its connections and those closed
type h3Server struct {
	port         xnet.Port
	hash, caHash [32]byte
	mu           sync.Mutex
	snis         []string
	conns        atomic.Int32
	closed       atomic.Int32
}

func newH3Server(t *testing.T, handler http.Handler) *h3Server {
	t.Helper()

	// ECDSA, as ChromeParrot offers no Ed25519, from a CA of its own
	ca, caHash := cert.MustGenerate(nil, cert.Authority(true), cert.KeyUsage(x509.KeyUsageCertSign))
	certificate, hash := cert.MustGenerate(ca, cert.DNSNames("www.googleapis.com", "oauth2.googleapis.com"))
	key, err := x509.ParsePKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	s := &h3Server{port: xnet.Port(conn.LocalAddr().(*net.UDPAddr).Port), hash: hash, caHash: caHash}
	server := &http3.Server{
		Handler: handler,
		TLSConfig: http3.ConfigureTLSConfig(&gotls.Config{
			Certificates: []gotls.Certificate{{Certificate: [][]byte{certificate.Certificate, ca.Certificate}, PrivateKey: key}},
			GetConfigForClient: func(hello *gotls.ClientHelloInfo) (*gotls.Config, error) {
				s.mu.Lock()
				s.snis = append(s.snis, hello.ServerName)
				s.mu.Unlock()
				return nil, nil
			},
		}),
		ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
			s.conns.Add(1)
			context.AfterFunc(c.Context(), func() { s.closed.Add(1) })
			return ctx
		},
	}
	go server.Serve(conn)
	t.Cleanup(func() {
		server.Close()
		conn.Close()
	})
	return s
}

// settings sends every host to the server over h3, through a destination built
// as TCP the way conf builds it, and pins the certificate of the server in config
func (s *h3Server) settings(config *tls.Config) *internet.MemoryStreamConfig {
	config.NextProtocol = []string{"h3"}
	config.PinnedPeerCertSha256 = [][]byte{s.hash[:]}
	return &internet.MemoryStreamConfig{
		ProtocolName:     protocolName,
		Destination:      &xnet.Destination{Address: xnet.LocalHostIP, Port: s.port, Network: xnet.Network_TCP},
		SecuritySettings: config,
	}
}

func (s *h3Server) seenSNIs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Sorted(slices.Values(s.snis))
}

// one client serves two hosts, and each gets its own SNI unless serverName
// says otherwise, which is also the name a pinned CA checks the certificate for
func TestServiceClientH3SNI(t *testing.T) {
	for _, c := range []struct {
		serverName string
		pinCA      bool
		want       []string
	}{
		{"", false, []string{"oauth2.googleapis.com", "www.googleapis.com"}},
		{"www.google.com", false, []string{"www.google.com", "www.google.com"}},
		{"", true, []string{"oauth2.googleapis.com", "www.googleapis.com"}},
	} {
		server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		settings := server.settings(&tls.Config{ServerName: c.serverName})
		if c.pinCA {
			settings.SecuritySettings.(*tls.Config).PinnedPeerCertSha256 = [][]byte{server.caHash[:]}
		}
		client := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8)
		for _, url := range []string{"https://www.googleapis.com/drive/v3/files", "https://oauth2.googleapis.com/token"} {
			resp, err := client.Get(url)
			if err != nil {
				t.Fatalf("serverName %q, pinned CA %v, %s: %v", c.serverName, c.pinCA, url, err)
			}
			resp.Body.Close()
			if resp.Proto != "HTTP/3.0" {
				t.Errorf("serverName %q, %s: went over %s", c.serverName, url, resp.Proto)
			}
		}
		if snis := server.seenSNIs(); !slices.Equal(snis, c.want) {
			t.Errorf("serverName %q: SNIs %v, want %v", c.serverName, snis, c.want)
		}
	}
}

// a request that stands still ends over h3 too, and says so
func TestServiceClientStallOverH3(t *testing.T) {
	const stall = 200 * time.Millisecond
	server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stuck" {
			w.Write([]byte("x"))
			w.(http.Flusher).Flush()
		}
		time.Sleep(5 * stall)
	}))
	client := newServiceClient(context.Background(), new(sync.Map), server.settings(&tls.Config{}), stall, 8)

	for _, path := range []string{"/stuck", "/silent"} {
		start := time.Now()
		resp, err := client.Get("https://www.googleapis.com" + path)
		if err == nil {
			if resp.Proto != "HTTP/3.0" {
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

// brutal and force-brutal, which are for Hysteria servers, give an error and
// no panic in a goroutine of http3, where XHTTP and DoH panic on brutal
func TestServiceClientH3Congestion(t *testing.T) {
	server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, cc := range []string{"", "bbr", "reno", "brutal", "force-brutal"} {
		settings := server.settings(&tls.Config{})
		settings.QuicParams = &internet.QuicParams{Congestion: cc, BrutalUp: 1 << 20}
		resp, err := newServiceClient(context.Background(), new(sync.Map), settings, 5*time.Second, 8).Get("https://www.googleapis.com/")
		if err == nil {
			resp.Body.Close()
		}
		if brutal := strings.HasSuffix(cc, "brutal"); brutal != (err != nil) || brutal && !strings.Contains(err.Error(), cc) {
			t.Errorf("congestion %q gave %v", cc, err)
		}
	}
}

// recordConn keeps the datagrams sent through it
type recordConn struct {
	net.PacketConn
	mu     sync.Mutex
	sent   [][]byte
	closed atomic.Bool
}

func (c *recordConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	c.sent = append(c.sent, bytes.Clone(p))
	c.mu.Unlock()
	return c.PacketConn.WriteTo(p, addr)
}

func (c *recordConn) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

// recorder dials UDP through recordConns and keeps them
type recorder struct {
	mu    sync.Mutex
	conns []*recordConn
}

func (r *recorder) dialUDP(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
	conn, err := internet.DialSystem(ctx, dest, nil)
	if err != nil {
		return nil, nil, err
	}
	rec := &recordConn{PacketConn: conn.(*xnet.PacketConnWrapper).PacketConn}
	r.mu.Lock()
	r.conns = append(r.conns, rec)
	r.mu.Unlock()
	return rec, conn.RemoteAddr(), nil
}

// a connection ends with its socket once it is idle for its idle timeout, as
// keepalive is off unless asked for, and so does one whose handshake failed,
// and neither leaves anything on the context that closes the connections
func TestServiceClientH3Closes(t *testing.T) {
	server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, pin := range [][]byte{server.hash[:], make([]byte, 32)} {
		rec := new(recorder)
		settings := server.settings(&tls.Config{})
		settings.SecuritySettings.(*tls.Config).PinnedPeerCertSha256 = [][]byte{pin}
		// ChromeParrot would keep the idle timeout at 30 s
		settings.QuicParams = &internet.QuicParams{MaxIdleTimeout: 1, DisableChromeParrot: true}
		settings.FinalMask = finalmask.NewFinalMask(nil, nil, nil, nil, rec.dialUDP, nil)
		connCtx := &afterFuncs{Context: ctx}
		resp, err := newServiceClient(connCtx, new(sync.Map), settings, 5*time.Second, 8).Get("https://www.googleapis.com/")
		if err == nil {
			resp.Body.Close()
		}
		if bytes.Equal(pin, server.hash[:]) != (err == nil) {
			t.Fatalf("pin %x: %v", pin[:4], err)
		}

		closed := func() bool {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			return len(rec.conns) == 1 && rec.conns[0].closed.Load()
		}
		for deadline := time.Now().Add(5 * time.Second); !closed() && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		if !closed() {
			t.Errorf("pin %x: the socket was left open", pin[:4])
		}
		waitFor(t, "the closed connection to leave the context", func() bool { return connCtx.live.Load() == 0 })
	}
}

// cncDialer gives UDP as a stream conn, the way dialerProxy does
type cncDialer struct{}

func (cncDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	conn, err := net.Dial("udp", dest.NetAddr())
	if err != nil {
		return nil, err
	}
	return cnc.NewConnection(cnc.ConnectionInput(conn), cnc.ConnectionOutput(conn), cnc.ConnectionOnClose(conn)), nil
}

func (cncDialer) DestIpAddress() net.IP { return nil }

// h3 goes over the stream conn of a dialerProxy too
func TestServiceClientH3DialerProxy(t *testing.T) {
	internet.UseAlternativeSystemDialer(cncDialer{})
	defer internet.UseAlternativeSystemDialer(nil)

	server := newH3Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	resp, err := newServiceClient(context.Background(), new(sync.Map), server.settings(&tls.Config{}), 5*time.Second, 8).Get("https://www.googleapis.com/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("went over %s", resp.Proto)
	}
}

// xdrive moves data over h3 to a fake Drive, with the noise of a UDP mask sent
// ahead of the Initial of each connection
func TestDriveOverH3(t *testing.T) {
	drive := newFakeDrive(t)
	server := newH3Server(t, drive.server.Config.Handler)
	driveTokenURL = "https://oauth2.googleapis.com/token"
	driveFilesURL = "https://www.googleapis.com/files"
	driveUploadURL = "https://www.googleapis.com/upload"

	rec := new(recorder)
	settings := server.settings(&tls.Config{})
	settings.ProtocolSettings = driveSettings().ProtocolSettings
	settings.ProtocolSettings.(*Config).Xmux = &splithttp.XmuxConfig{MaxConnections: &splithttp.RangeConfig{From: 4, To: 4}}
	masks := []finalmask.UDPMask{&noise.Config{Items: []*noise.Item{{Packet: []byte("noise")}}}}
	settings.FinalMask = finalmask.NewFinalMask(nil, masks, nil, nil, rec.dialUDP, nil)

	client, srv, cleanup := pairWith(t, settings)
	defer cleanup()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	expectRead(t, srv, "ping")
	if _, err := srv.Write([]byte("pong")); err != nil {
		t.Fatalf("server write: %v", err)
	}
	expectRead(t, client, "pong")

	payload := make([]byte, 300000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	go client.Write(payload)
	if err := srv.SetReadDeadline(time.Now().Add(testPatience)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(srv, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	// one for the listener to www.googleapis.com, one for the token to
	// oauth2.googleapis.com and one of XMUX for each end of the session
	if len(rec.conns) != 4 {
		t.Errorf("%d connections went through the mask, want 4", len(rec.conns))
	}
	for i, conn := range rec.conns {
		conn.mu.Lock()
		sent := conn.sent
		conn.mu.Unlock()
		if len(sent) < 2 {
			t.Errorf("connection %d sent %d datagrams", i, len(sent))
			continue
		}
		// the noise, then a QUIC v1 Initial of 1250 bytes with no source
		// connection ID, as ChromeParrot sends it
		first, initial := sent[0], sent[1]
		if string(first) != "noise" || len(initial) != 1250 || initial[0]&0xf0 != 0xc0 || !bytes.Equal(initial[1:5], []byte{0, 0, 0, 1}) || initial[6+int(initial[5])] != 0 {
			t.Errorf("connection %d began with %q and %d bytes %x", i, first, len(initial), initial[:min(len(initial), 24)])
		}
	}
}

// over h3 a connection of XMUX is a QUIC connection, which closes once XMUX
// drops it, so that the server hears of it
func TestDriveXmuxOverH3(t *testing.T) {
	drive := newFakeDrive(t)
	server := newH3Server(t, drive.server.Config.Handler)
	driveTokenURL = "https://www.googleapis.com/token"
	driveFilesURL = "https://www.googleapis.com/files"
	driveUploadURL = "https://www.googleapis.com/upload"
	settings := server.settings(&tls.Config{})
	settings.ProtocolSettings = driveSettings().ProtocolSettings
	settings.ProtocolSettings.(*Config).Xmux = &splithttp.XmuxConfig{HMaxRequestTimes: &splithttp.RangeConfig{From: 3, To: 3}}
	storage, err := newDriveStorage(settings, settings.ProtocolSettings.(*Config))
	if err != nil {
		t.Fatalf("newDriveStorage: %v", err)
	}
	session := sessionStorage(storage)
	defer session.Close()

	for _, name := range []string{"a", "b", "c", "d"} {
		if err := session.Put(context.Background(), "streams/abc/c2s/"+name, []byte("x")); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	// one for the token, the first of XMUX for 3 requests and one more
	if n := server.conns.Load(); n != 3 {
		t.Errorf("the token and 4 requests with 3 to a connection took %d connections", n)
	}
	waitFor(t, "the first connection of XMUX to close", func() bool { return server.closed.Load() == 1 })
}
