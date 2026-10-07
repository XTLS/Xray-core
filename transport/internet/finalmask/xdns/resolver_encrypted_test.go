package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/dns/dnsmessage"
)

func resolverQuery(t *testing.T, name string) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
	}
	query, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func resolverReply(query []byte) []byte {
	response := append([]byte(nil), query...)
	response[2] |= 0x80
	return response
}

func testResolverDialer() *finalmask.Dialer {
	return &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
	}}
}

func newTestDOH(t *testing.T, server *httptest.Server, trust bool) (*encryptedResolver, *dohTransport) {
	t.Helper()
	cfg, err := ParseResolverAddr("doh://" + strings.TrimPrefix(server.URL, "https://") + "/custom?key=value")
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver(cfg, testResolverDialer())
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.(*encryptedResolver)
	transport := r.transport.(*dohTransport)
	if trust {
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		transport.transport.TLSClientConfig.RootCAs = roots
	}
	t.Cleanup(r.Close)
	return r, transport
}

func TestDOHExchangeAndReuse(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.RequestURI() != "/custom?key=value" || req.Header.Get("Content-Type") != "application/dns-message" || req.Header.Get("Accept") != "application/dns-message" || req.ProtoMajor != 2 {
			t.Errorf("unexpected request: %s %s %s", req.Method, req.URL, req.Proto)
		}
		query, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(resolverReply(query))
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	_, transport := newTestDOH(t, server, true)
	query := resolverQuery(t, "a.example.")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 2 {
		response, err := transport.Exchange(ctx, query)
		if err != nil || !bytes.Equal(response, resolverReply(query)) {
			t.Fatalf("response %x, error %v", response, err)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("opened %d connections, want 1", got)
	}
}

func TestDOHRejectsInvalidResponses(t *testing.T) {
	for _, mode := range []string{"status", "type", "oversize", "short", "question", "id", "redirect", "certificate"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests.Add(1)
				query, _ := io.ReadAll(req.Body)
				w.Header().Set("Content-Type", "application/dns-message")
				response := resolverReply(query)
				switch mode {
				case "status":
					w.WriteHeader(http.StatusBadGateway)
				case "type":
					w.Header().Set("Content-Type", "text/html")
				case "oversize":
					response = make([]byte, resolverMaxResponse+1)
				case "short":
					response = []byte{0}
				case "question":
					response = resolverReply(resolverQuery(t, "other.example."))
				case "id":
					response[0]++
				case "redirect":
					w.Header().Set("Location", "/elsewhere")
					w.WriteHeader(http.StatusTemporaryRedirect)
				}
				_, _ = w.Write(response)
			}))
			defer server.Close()
			_, transport := newTestDOH(t, server, mode != "certificate")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := transport.Exchange(ctx, resolverQuery(t, "a.example.")); err == nil {
				t.Fatal("accepted invalid response")
			}
			if mode == "redirect" && requests.Load() != 1 {
				t.Fatal("followed redirect")
			}
		})
	}
}

func TestDOTOutOfOrderAndReuse(t *testing.T) {
	// The HTTPS fixture supplies a certificate; the DNS listener speaks only
	// TLS with two-byte DNS framing, and replies in reverse request order.
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: fixture.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		var queries [][]byte
		for range 2 {
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				serverErr <- err
				return
			}
			query := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, err := io.ReadFull(conn, query); err != nil {
				serverErr <- err
				return
			}
			queries = append(queries, query)
		}
		if bytes.Equal(queries[0][:2], queries[1][:2]) {
			serverErr <- errors.New("duplicate in-flight transaction IDs")
			return
		}
		for i := 1; i >= 0; i-- {
			response := resolverReply(queries[i])
			frame := make([]byte, len(response)+2)
			binary.BigEndian.PutUint16(frame, uint16(len(response)))
			copy(frame[2:], response)
			// Fragment the framing header to exercise ReadFull.
			if _, err := conn.Write(frame[:1]); err != nil {
				serverErr <- err
				return
			}
			if _, err := conn.Write(frame[1:]); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()
	cfg := &ResolverProto{Type: "dot", Addr: listener.Addr().String()}
	resolver, err := NewResolver(cfg, testResolverDialer())
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	transport := resolver.(*encryptedResolver).transport.(*dotTransport)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	transport.tlsConfig.RootCAs = roots
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, name := range []string{"a.example.", "b.example."} {
		query := resolverQuery(t, name)
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := transport.Exchange(ctx, query)
			if err != nil || !bytes.Equal(response, resolverReply(query)) {
				t.Errorf("response %x, error %v", response, err)
			}
		}()
	}
	wg.Wait()
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("DNS fixture did not finish")
	}
}

type blockedEncryptedTransport struct {
	started chan struct{}
	active  atomic.Int32
}

func (r *blockedEncryptedTransport) Exchange(ctx context.Context, _ []byte) ([]byte, error) {
	r.active.Add(1)
	defer r.active.Add(-1)
	r.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *blockedEncryptedTransport) Close() {}

func TestEncryptedResolverBoundedAndClose(t *testing.T) {
	transport := &blockedEncryptedTransport{started: make(chan struct{}, resolverMaxConcurrent)}
	r := newEncryptedResolver(transport, xnet.TCPDestination(xnet.LocalHostIP, 853))
	query := resolverQuery(t, "a.example.")
	for range 2 * resolverMaxConcurrent {
		r.Send(query)
	}
	for range resolverMaxConcurrent {
		select {
		case <-transport.started:
		case <-time.After(3 * time.Second):
			t.Fatal("workers did not start")
		}
	}
	if transport.active.Load() != resolverMaxConcurrent {
		t.Fatal("concurrency limit not enforced")
	}
	done := make(chan struct{})
	go func() {
		r.Close()
		r.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not cancel requests")
	}
	r.Send(query)
	if _, err := r.Read(make([]byte, 4096)); err != io.ErrClosedPipe || transport.active.Load() != 0 {
		t.Fatalf("read error %v, active %d", err, transport.active.Load())
	}
}

func TestDOHCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		started <- struct{}{}
		<-req.Context().Done()
	}))
	defer server.Close()
	r, _ := newTestDOH(t, server, true)
	r.Send(resolverQuery(t, "a.example."))
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not finish")
	}
}

type noWriteDeadlineConn struct{ net.Conn }

func (c noWriteDeadlineConn) SetWriteDeadline(time.Time) error { return nil }

func TestDOTCancelsBlockedProxyWrite(t *testing.T) {
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer fixture.Close()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	handshake := make(chan error, 1)
	release := make(chan struct{})
	defer close(release)
	go func() {
		conn := tls.Server(serverConn, &tls.Config{Certificates: fixture.TLS.Certificates})
		handshake <- conn.Handshake()
		// No reader consumes the DNS frame: the client's Write must be
		// interrupted by Close because this proxy ignores write deadlines.
		<-release
	}()
	dialer := &finalmask.Dialer{DialTCPContext: func(context.Context, xnet.Destination) (net.Conn, error) {
		return noWriteDeadlineConn{clientConn}, nil
	}}
	resolver, err := NewDOTResolver(&ResolverProto{Type: "dot", Addr: "127.0.0.1:853"}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	// Ensure even a failing regression test unblocks the stream before Close.
	defer clientConn.Close()
	transport := resolver.(*encryptedResolver).transport.(*dotTransport)
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	transport.tlsConfig.RootCAs = roots
	query := resolverQuery(t, "a.example.")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := transport.Exchange(ctx, query); done <- err }()
	select {
	case err := <-handshake:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TLS handshake did not finish")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write unexpectedly succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request cancellation did not interrupt the proxy write")
	}
	closed := make(chan struct{})
	go func() { resolver.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked on a canceled proxy write")
	}
}

func TestDOHTunnelRecordTypes(t *testing.T) {
	for _, qtype := range []uint16{TypeTXT, TypeA, TypeAAAA} {
		t.Run(dnsmessage.Type(qtype).String(), func(t *testing.T) {
			domain, err := NewDomain("tunnel.example", 255, 63, []uint16{qtype}, 1232)
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte("encrypted tunnel payload")
			framed := append([]byte{0xC0, byte(len(payload))}, payload...)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				query, _ := io.ReadAll(req.Body)
				var msg dnsmessage.Message
				if err := msg.Unpack(query); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				response := NewResp(msg, domain, 1232).Encode(nil, framed)
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(response)
			}))
			defer server.Close()
			r, _ := newTestDOH(t, server, true)
			var data [17]byte
			data[0] = TypeMap[qtype]
			msg := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
				Questions: []dnsmessage.Question{{Name: domain.Encode(data[:]), Type: dnsmessage.Type(qtype), Class: dnsmessage.ClassINET}},
			}
			query, err := msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			r.Send(query)
			done := make(chan []byte, 1)
			go func() {
				response := make([]byte, 4096)
				n, _ := r.Read(response)
				done <- response[:n]
			}()
			select {
			case response := <-done:
				client := &xdnsClient{domains: []*Domain{domain}, readCh: make(chan packet, 1), closeCh: make(chan struct{})}
				if !client.read(response, r.Addr()) {
					t.Fatal("could not decode tunnel response")
				}
				if got := <-client.readCh; !bytes.Equal(got.p, payload) {
					t.Fatalf("decoded %q, want %q", got.p, payload)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("encrypted resolver did not deliver response")
			}
		})
	}
}
