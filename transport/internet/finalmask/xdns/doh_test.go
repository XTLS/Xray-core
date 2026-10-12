package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

type httpResolverTestFactory func(*ResolverProto, *finalmask.Dialer) (Resolver, error)
type httpResolverTestGateway func(*testing.T, http.Handler) (string, *ResolverProto, *finalmask.Dialer)

func startDoHTestGateway(t *testing.T, handler http.Handler) (string, *ResolverProto, *finalmask.Dialer) {
	t.Helper()
	cert, ca := resolverTestCertificate(t)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://resolver.test:" + port + "/dns%2Dquery?token=a%2Fb&x=1&x=2"
	config := &ResolverProto{
		Type: "https", Addr: endpoint, Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Usage: xtls.Certificate_AUTHORITY_VERIFY, Certificate: ca}},
	}
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		if dest.Network != xnet.Network_TCP || dest.Address.String() != "127.0.0.1" || strconv.Itoa(int(dest.Port)) != port {
			t.Errorf("wrong bootstrap destination: %v", dest)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
	}}
	return endpoint, config, dialer
}

func httpTestQuery(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 1232},
			Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 65001, Data: []byte{0, 255, 1, 128}}}},
		}},
	}
	wire, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func httpTestResponse(t *testing.T, query []byte) []byte {
	t.Helper()
	var msg dnsmessage.Message
	if err := msg.Unpack(query); err != nil {
		t.Error(err)
		return nil
	}
	msg.Header.Response = true
	msg.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: msg.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 60},
		Body: &dnsmessage.TXTResource{TXT: []string{"\x00\xff\x01\x80wire", "second"}},
	}}
	wire, err := msg.Pack()
	if err != nil {
		t.Error(err)
	}
	return wire
}

func httpTestRead(t *testing.T, resolver Resolver) []byte {
	t.Helper()
	type result struct { p []byte; err error }
	ch := make(chan result, 1)
	go func() {
		p := make([]byte, 4096)
		n, err := resolver.Read(p)
		ch <- result{p[:n], err}
	}()
	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.p
	case <-time.After(3 * time.Second):
		resolver.Close()
		t.Fatal("DNS response did not arrive")
		return nil
	}
}

func testHTTPResolverWire(t *testing.T, factory httpResolverTestFactory, gateway httpResolverTestGateway, proto int) {
	t.Helper()
	query := httpTestQuery(t, 0x1234, "binary.example.")
	wireQuery := bytes.Clone(query)
	wireQuery[0], wireQuery[1] = 0, 0
	var calls atomic.Int32
	endpoint, config, dialer := gateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.ProtoMajor != proto || r.TLS.NegotiatedProtocol != map[int]string{2: "h2", 3: "h3"}[proto] {
			t.Errorf("wrong HTTP exchange: %s %s ALPN=%s", r.Method, r.Proto, r.TLS.NegotiatedProtocol)
		}
		if !strings.HasPrefix(r.Host, "resolver.test:") || r.TLS.ServerName != "resolver.test" || r.RequestURI != "/dns%2Dquery?token=a%2Fb&x=1&x=2" {
			t.Errorf("origin or URL changed: authority=%s SNI=%s URI=%s", r.Host, r.TLS.ServerName, r.RequestURI)
		}
		if r.Header.Get("Accept") != "application/dns-message" || r.Header.Get("Content-Type") != "application/dns-message" {
			t.Error("DNS media type missing")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, wireQuery) {
			t.Errorf("POST is not the original DNS wire message with ID=0: %x, %v", body, err)
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(httpTestResponse(t, body))
	}))
	if endpoint != config.Addr {
		t.Fatal("gateway returned mismatched endpoint")
	}
	var dials atomic.Int32
	if proto == 2 {
		dial := dialer.DialTCPContext
		dialer.DialTCPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) { dials.Add(1); return dial(ctx, dest) }
	} else {
		dial := dialer.DialUDPContext
		dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) { dials.Add(1); return dial(ctx, dest) }
	}
	resolver, err := factory(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	want := httpTestResponse(t, query)
	for range 2 {
		if err := resolver.Send(query); err != nil {
			t.Fatal(err)
		}
		if got := httpTestRead(t, resolver); !bytes.Equal(got, want) {
			t.Fatalf("DNS response lost content or original ID: %x", got)
		}
	}
	if !bytes.Equal(query, httpTestQuery(t, 0x1234, "binary.example.")) || calls.Load() != 2 || dials.Load() != 1 {
		t.Fatalf("query mutation or connection reuse failure: requests=%d dials=%d", calls.Load(), dials.Load())
	}
}

func TestDoHWireAndReuse(t *testing.T) { testHTTPResolverWire(t, NewDoHResolver, startDoHTestGateway, 2) }

func testHTTPResolverClose(t *testing.T, factory httpResolverTestFactory, gateway httpResolverTestGateway) {
	t.Helper()
	started := make(chan struct{})
	canceled := make(chan struct{})
	_, config, dialer := gateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	resolver, err := factory(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	if err := resolver.Send(httpTestQuery(t, 9, "slow.example.")); err != nil { t.Fatal(err) }
	select {
	case <-started:
	case <-time.After(3 * time.Second): t.Fatal("HTTP request did not start")
	}
	closed := make(chan struct{})
	go func() { resolver.Close(); resolver.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second): t.Fatal("Close blocked on response body")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second): t.Fatal("Close did not cancel HTTP stream")
	}
	if err := resolver.Send(httpTestQuery(t, 10, "closed.example.")); !errors.Is(err, io.ErrClosedPipe) { t.Fatalf("Send after Close: %v", err) }
	if _, err := resolver.Read(make([]byte, 4096)); !errors.Is(err, io.ErrClosedPipe) { t.Fatalf("Read after Close: %v", err) }
}

func TestDoHCloseCancelsBody(t *testing.T) { testHTTPResolverClose(t, NewDoHResolver, startDoHTestGateway) }

func testHTTPResolverCloseDial(t *testing.T, factory httpResolverTestFactory, h3 bool) {
	t.Helper()
	started := make(chan struct{})
	canceled := make(chan struct{})
	block := func(ctx context.Context, dest xnet.Destination) (net.Conn,error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	config := &ResolverProto{Type: "https", Addr: "https://resolver.test/dns-query", Bootstrap: "127.0.0.1"}
	dialer := &finalmask.Dialer{DialTCPContext: block}
	if h3 { config.Type = "https+h3"; dialer.DialTCPContext = nil; dialer.DialUDPContext = block }
	resolver, err := factory(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	if err := resolver.Send(httpTestQuery(t, 1, "dial.example.")); err != nil { t.Fatal(err) }
	select { case <-started: case <-time.After(time.Second): t.Fatal("dial did not start") }
	done := make(chan struct{})
	go func() { resolver.Close(); close(done) }()
	select { case <-done: case <-time.After(time.Second): t.Fatal("Close did not interrupt dial") }
	select { case <-canceled: default: t.Fatal("dial still running after Close") }
}

func TestDoHCloseCancelsDial(t *testing.T) { testHTTPResolverCloseDial(t, NewDoHResolver, false) }

func testHTTPResolverOutOfOrder(t *testing.T, factory httpResolverTestFactory, gateway httpResolverTestGateway) {
	t.Helper()
	firstStarted := make(chan struct{})
	release := make(chan struct{})
	_, config, dialer := gateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Error(err); return }
		var msg dnsmessage.Message
		if err := msg.Unpack(body); err != nil { t.Error(err); return }
		if msg.Questions[0].Name.String() == "first.example." {
			close(firstStarted)
			select { case <-release: case <-r.Context().Done(): return }
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(httpTestResponse(t, body))
	}))
	resolver, err := factory(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	first := httpTestQuery(t, 77, "first.example.")
	second := httpTestQuery(t, 77, "second.example.")
	if err := resolver.Send(first); err != nil { t.Fatal(err) }
	select { case <-firstStarted: case <-time.After(3*time.Second): t.Fatal("first request did not start") }
	if err := resolver.Send(second); err != nil { t.Fatal(err) }
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, second)) { t.Fatal("out-of-order response associated with wrong query") }
	close(release)
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, first)) { t.Fatal("first response associated with wrong query") }
}

func TestDoHOutOfOrder(t *testing.T) { testHTTPResolverOutOfOrder(t, NewDoHResolver, startDoHTestGateway) }

func testHTTPResolverErrors(t *testing.T, factory httpResolverTestFactory, gateway httpResolverTestGateway) {
	t.Helper()
	for _, failure := range []string{"status", "media", "id", "question", "redirect"} {
		t.Run(failure, func(t *testing.T) {
			badServed := make(chan struct{})
			var calls atomic.Int32
			_, config, dialer := gateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/forward" {
					t.Error("DoH followed a redirect")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil { t.Error(err); return }
				var msg dnsmessage.Message
				if err := msg.Unpack(body); err != nil { t.Error(err); return }
				isBad := msg.Questions[0].Name.String() == "bad.example."
				response := httpTestResponse(t, body)
				w.Header().Set("Content-Type", "application/dns-message")
				if isBad {
					defer close(badServed)
					switch failure {
					case "status": w.WriteHeader(http.StatusTooManyRequests)
					case "media": w.Header().Set("Content-Type", "application/json")
					case "id": response[1] = 1
					case "question": response = httpTestResponse(t, httpTestQuery(t, 0, "other.example."))
					case "redirect":
						w.Header().Set("Location", "https://"+r.Host+"/forward")
						w.WriteHeader(http.StatusSeeOther)
					}
				}
				_, _ = w.Write(response)
			}))
			resolver, err := factory(config, dialer)
			if err != nil { t.Fatal(err) }
			t.Cleanup(resolver.Close)
			if err := resolver.Send(httpTestQuery(t, 77, "bad.example.")); err != nil { t.Fatal(err) }
			select { case <-badServed: case <-time.After(3*time.Second): t.Fatal("bad request did not arrive") }
			good := httpTestQuery(t, 77, "good.example.")
			if err := resolver.Send(good); err != nil { t.Fatal(err) }
			if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, good)) { t.Fatal("invalid response delivered or resolver stopped receiving") }
			if calls.Load() != 2 { t.Fatalf("request was replayed or redirected: %d calls", calls.Load()) }
		})
	}
}

func TestDoHRequestErrorsDoNotStopRead(t *testing.T) { testHTTPResolverErrors(t, NewDoHResolver, startDoHTestGateway) }

func TestDoHRejectsEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://resolver.test/dns-query", "https:///dns-query", "https://u:p@resolver.test/", "https://resolver.test/#fragment", "https://resolver.test/#", "https://resolver.test:0/", "https://resolver.test:70000/", "https://resolver.test:/"} {
		t.Run(endpoint, func(t *testing.T) {
			dialer := &finalmask.Dialer{DialTCPContext: func(context.Context, xnet.Destination) (net.Conn,error) { return nil, io.ErrClosedPipe }}
			if resolver, err := NewDoHResolver(&ResolverProto{Type: "https", Addr: endpoint}, dialer); err == nil { resolver.Close(); t.Fatal("invalid endpoint accepted") }
		})
	}
}

func TestDoHRejectsWrongALPN(t *testing.T) {
	cert, ca := resolverTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = listener.Close() })
	checked := make(chan struct{})
	go func() {
		defer close(checked)
		conn, err := listener.Accept()
		if err != nil { return }
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2*time.Second))
		if err := conn.(*tls.Conn).Handshake(); err != nil { return }
		if n, _ := conn.Read(make([]byte, 1)); n != 0 { t.Error("DoH sent HTTP bytes without negotiating h2") }
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	config := &ResolverProto{Type: "https", Addr: "https://resolver.test:"+port+"/dns-query", Bootstrap: "127.0.0.1", Certificates: []*xtls.Certificate{{Usage: xtls.Certificate_AUTHORITY_VERIFY, Certificate: ca}}}
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn,error) { return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr()) }}
	resolver, err := NewDoHResolver(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	if err := resolver.Send(httpTestQuery(t, 1, "alpn.example.")); err != nil { t.Fatal(err) }
	select { case <-checked: case <-time.After(3*time.Second): t.Fatal("DoH did not finish rejected ALPN handshake") }
	resolver.Close()
}

type httpTestTrackedConn struct { net.Conn; once sync.Once; closed chan struct{} }
func (c *httpTestTrackedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); close(c.closed) })
	return err
}

func TestDoHRejectsCertificate(t *testing.T) {
	for _, failure := range []string{"untrusted", "hostname"} {
		t.Run(failure, func(t *testing.T) {
			var served atomic.Int32
			_, config, dialer := startDoHTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1); w.WriteHeader(http.StatusInternalServerError) }))
			if failure == "untrusted" { config.Certificates = nil } else { config.Addr = strings.Replace(config.Addr, "resolver.test", "wrong.example", 1) }
			closed := make(chan struct{})
			dial := dialer.DialTCPContext
			dialer.DialTCPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn,error) {
				conn, err := dial(ctx, dest)
				if err != nil { return nil, err }
				return &httpTestTrackedConn{Conn: conn, closed: closed}, nil
			}
			resolver, err := NewDoHResolver(config, dialer)
			if err != nil { t.Fatal(err) }
			t.Cleanup(resolver.Close)
			if err := resolver.Send(httpTestQuery(t, 1, "identity.example.")); err != nil { t.Fatal(err) }
			select { case <-closed: case <-time.After(3*time.Second): t.Fatal("rejected TLS identity leaked TCP connection") }
			if served.Load() != 0 { t.Fatal("DoH submitted tunnel query without a verified certificate") }
		})
	}
}

func testHTTPResolverReconnect(t *testing.T, factory httpResolverTestFactory, gateway httpResolverTestGateway, proto int) {
	t.Helper()
	var requests atomic.Int32
	_, config, dialer := gateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil { t.Error(err); return }
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(httpTestResponse(t, body))
	}))
	var raw io.Closer
	closed := make(chan struct{})
	created := make(chan struct{})
	var dials atomic.Int32
	if proto == 2 {
		dial := dialer.DialTCPContext
		dialer.DialTCPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn,error) {
			conn, err := dial(ctx, dest)
			if err != nil { return nil, err }
			if dials.Add(1) == 1 {
				raw = conn
				close(created)
				return &httpTestTrackedConn{Conn: conn, closed: closed}, nil
			}
			return conn, nil
		}
	} else {
		dial := dialer.DialUDPContext
		dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn,error) {
			conn, err := dial(ctx, dest)
			if err != nil { return nil, err }
			if dials.Add(1) == 1 {
				wrapper := conn.(*xnet.PacketConnWrapper)
				raw = wrapper.PacketConn
				wrapper.PacketConn = &httpTestTrackedPacketConn{PacketConn: wrapper.PacketConn, closed: closed}
				close(created)
			}
			return conn, nil
		}
	}
	resolver, err := factory(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(resolver.Close)
	first := httpTestQuery(t, 20, "before.example.")
	if err := resolver.Send(first); err != nil { t.Fatal(err) }
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, first)) { t.Fatal("first exchange failed") }
	<-created
	_ = raw.Close()
	select { case <-closed: case <-time.After(time.Second): t.Fatal("broken connection was not retired") }
	second := httpTestQuery(t, 21, "after.example.")
	if err := resolver.Send(second); err != nil { t.Fatal(err) }
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, second)) { t.Fatal("resolver did not recover with a subsequent query") }
	if dials.Load() != 2 || requests.Load() != 2 { t.Fatalf("reconnect replayed a submitted query: dials=%d requests=%d", dials.Load(), requests.Load()) }
}

func TestDoHReconnectsWithoutReplay(t *testing.T) { testHTTPResolverReconnect(t, NewDoHResolver, startDoHTestGateway, 2) }

func TestDoHResponseValidation(t *testing.T) {
	query := httpTestQuery(t, 0x1234, "checks.example.")
	wireQuery := bytes.Clone(query)
	wireQuery[0], wireQuery[1] = 0, 0
	valid := httpTestResponse(t, wireQuery)
	for _, tc := range []struct { name string; status int; media string; body []byte; streaming bool; wantError bool }{
		{"ok", 200, "application/dns-message", valid, false, false},
		{"media-parameters", 200, "Application/DNS-Message; charset=binary", valid, false, false},
		{"status", 429, "application/dns-message", valid, false, true},
		{"wrong-media", 200, "application/json", valid, false, true},
		{"missing-media", 200, "", valid, false, true},
		{"malformed-media", 200, "application/dns-message;broken", valid, false, true},
		{"empty", 200, "application/dns-message", nil, false, true},
		{"short", 200, "application/dns-message", make([]byte, 11), false, true},
		{"wrong-id", 200, "application/dns-message", httpTestResponse(t, query), false, true},
		{"oversize-known", 200, "application/dns-message", make([]byte, 4097), false, true},
		{"oversize-stream", 200, "application/dns-message", make([]byte, 4097), true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.media)
				if !tc.streaming { w.Header().Set("Content-Length", strconv.Itoa(len(tc.body))) }
				w.WriteHeader(tc.status)
				if tc.streaming { w.(http.Flusher).Flush() }
				_, _ = w.Write(tc.body)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := exchangeDoH(ctx, server.Client(), server.URL, bytes.Clone(query))
			if (err != nil) != tc.wantError { t.Fatalf("response validation error: %v", err) }
			if !tc.wantError {
				want := bytes.Clone(valid)
				binary.BigEndian.PutUint16(want[:2], 0x1234)
				if !bytes.Equal(got, want) { t.Fatal("response ID not restored") }
			}
		})
	}
}

type httpTestRoundTripper func(*http.Request) (*http.Response, error)
func (f httpTestRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDoHPostCannotReplayBody(t *testing.T) {
	query := httpTestQuery(t, 42, "replay.example.")
	client := &http.Client{Transport: httpTestRoundTripper(func(req *http.Request) (*http.Response,error) {
		defer req.Body.Close()
		if req.GetBody != nil { t.Error("POST permits replay of tunnel data") }
		if req.Header.Get("Cache-Control") != "no-store" { t.Error("request permits local HTTP caching") }
		return nil, io.ErrUnexpectedEOF
	})}
	if _, err := exchangeDoH(context.Background(), client, "https://resolver.test/dns-query", query); err == nil { t.Fatal("transport failure ignored") }
}

func TestDoHBodyDeadline(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	query := httpTestQuery(t, 1, "deadline.example.")
	go func() { _, err := exchangeDoH(ctx, server.Client(), server.URL, query); result <- err }()
	select { case <-started: case <-time.After(time.Second): t.Fatal("response body did not start") }
	cancel()
	select {
	case err := <-result: if !errors.Is(err, context.Canceled) { t.Fatalf("body ignored request cancellation: %v", err) }
	case <-time.After(time.Second): t.Fatal("body read did not cancel")
	}
}
