package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

func tlsResolverTestQuery(t *testing.T, name string, id uint16) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Type: dnsmessage.TypeOPT, Class: 4096},
			Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 12, Data: []byte{0, 255, 1}}}},
		}},
	}
	p, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tlsResolverTestResponse(query []byte) ([]byte, error) {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil {
		return nil, err
	}
	m.Header.Response = true
	m.Answers = []dnsmessage.Resource{{
		Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
		Body: &dnsmessage.TXTResource{TXT: []string{string([]byte{0, 255, 1, 128})}},
	}}
	return m.Pack()
}

func tlsResolverReadFrame(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(header[:]))
	_, err := io.ReadFull(r, message)
	return message, err
}

func tlsResolverWriteFrame(w io.Writer, p []byte) error {
	frame := make([]byte, len(p)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(p)))
	copy(frame[2:], p)
	n, err := w.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	return err
}

func startDoTServer(t *testing.T, protocols []string, handle func(context.Context, *tls.Conn)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	certificate, pem := resolverTestCertificate(t)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: protocols, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	conns := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(conns, conn); mu.Unlock() }()
				tlsConn := conn.(*tls.Conn)
				if tlsConn.HandshakeContext(ctx) == nil {
					handle(ctx, tlsConn)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-accepted
		mu.Lock()
		for conn := range conns {
			conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := &ResolverProto{
		Type: "tls", Addr: net.JoinHostPort("resolver.test", port), Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Certificate: pem, Usage: xtls.Certificate_AUTHORITY_VERIFY}},
	}
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dest.NetAddr())
	}}
	return config, dialer
}

func startDoTGateway(t *testing.T, exchange func(context.Context, []byte) ([]byte, error)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	return startDoTServer(t, []string{"dot"}, func(ctx context.Context, conn *tls.Conn) {
		var writes sync.Mutex
		var responses sync.WaitGroup
		defer responses.Wait()
		for {
			query, err := tlsResolverReadFrame(conn)
			if err != nil {
				return
			}
			responses.Add(1)
			go func() {
				defer responses.Done()
				response, err := exchange(ctx, query)
				if err == nil {
					writes.Lock()
					defer writes.Unlock()
					tlsResolverWriteFrame(conn, response)
				}
			}()
		}
	})
}

func tlsResolverRead(t *testing.T, r Resolver) []byte {
	t.Helper()
	result := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		p := make([]byte, 4096)
		n, err := r.Read(p)
		if err != nil {
			errCh <- err
			return
		}
		result <- p[:n]
	}()
	select {
	case p := <-result:
		return p
	case err := <-errCh:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("resolver response timed out")
	}
	return nil
}

func TestDoTUniqueIDsOutOfOrderAndWirePreservation(t *testing.T) {
	queries := make(chan []byte, 2)
	release := make(chan struct{})
	config, dialer := startDoTGateway(t, func(ctx context.Context, query []byte) ([]byte, error) {
		queries <- bytes.Clone(query)
		var m dnsmessage.Message
		if err := m.Unpack(query); err != nil {
			return nil, err
		}
		if m.Questions[0].Name.String() == "first.example." {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return tlsResolverTestResponse(query)
	})
	r, err := NewDoTResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	first := tlsResolverTestQuery(t, "first.example.", 99)
	second := tlsResolverTestQuery(t, "second.example.", 99)
	if err := r.Send(first); err != nil {
		t.Fatal(err)
	}
	if err := r.Send(second); err != nil {
		t.Fatal(err)
	}
	p := tlsResolverRead(t, r)
	want, _ := tlsResolverTestResponse(second)
	if !bytes.Equal(p, want) {
		t.Fatal("out-of-order response lost original ID or DNS payload")
	}
	close(release)
	p = tlsResolverRead(t, r)
	want, _ = tlsResolverTestResponse(first)
	if !bytes.Equal(p, want) {
		t.Fatal("first response lost original ID or DNS payload")
	}
	a, b := <-queries, <-queries
	if binary.BigEndian.Uint16(a[:2]) == binary.BigEndian.Uint16(b[:2]) {
		t.Fatal("duplicate wire ID on one DoT connection")
	}
	if binary.BigEndian.Uint16(first[:2]) != 99 || binary.BigEndian.Uint16(second[:2]) != 99 {
		t.Fatal("Send modified caller-owned DNS message")
	}
}

func TestDoTRejectsCertificateIdentityAndAcceptsNoALPN(t *testing.T) {
	config, dialer := startDoTServer(t, nil, func(ctx context.Context, conn *tls.Conn) {
		query, err := tlsResolverReadFrame(conn)
		if err == nil {
			response, _ := tlsResolverTestResponse(query)
			tlsResolverWriteFrame(conn, response)
		}
	})
	query := tlsResolverTestQuery(t, "test.example.", 42)
	for _, name := range []string{"wrong.example", "resolver.test"} {
		config.ServerName = name
		r, err := NewDoTResolver(config, dialer)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		response, err := r.(*DoTResolver).exchange(ctx, bytes.Clone(query))
		cancel()
		r.Close()
		if name == "wrong.example" && err == nil {
			t.Fatal("accepted wrong TLS identity")
		}
		if name == "resolver.test" && (err != nil || binary.BigEndian.Uint16(response[:2]) != 42) {
			t.Fatalf("dedicated DoT endpoint without ALPN rejected: %v", err)
		}
	}
}

func TestDoTReconnectsAfterHalfFrameWithoutReplay(t *testing.T) {
	var received atomic.Int32
	config, dialer := startDoTServer(t, []string{"dot"}, func(ctx context.Context, conn *tls.Conn) {
		query, err := tlsResolverReadFrame(conn)
		if err != nil {
			return
		}
		if received.Add(1) == 1 {
			conn.Write([]byte{0, 30, 1})
			return
		}
		response, _ := tlsResolverTestResponse(query)
		tlsResolverWriteFrame(conn, response)
	})
	r, err := NewDoTResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	query := tlsResolverTestQuery(t, "test.example.", 42)
	if _, err := r.(*DoTResolver).exchange(ctx, bytes.Clone(query)); err == nil {
		t.Fatal("accepted truncated DoT frame")
	}
	response, err := r.(*DoTResolver).exchange(ctx, bytes.Clone(query))
	if err != nil || binary.BigEndian.Uint16(response[:2]) != 42 {
		t.Fatalf("next query did not reconnect: %v", err)
	}
	if received.Load() != 2 {
		t.Fatal("submitted query was automatically replayed")
	}
}

func TestDoTCloseCancelsHandshake(t *testing.T) {
	started := make(chan struct{}, 1)
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { <-ctx.Done(); server.Close() }()
		started <- struct{}{}
		return client, nil
	}}
	r, err := NewDoTResolver(&ResolverProto{Addr: "resolver.test:853", Bootstrap: "127.0.0.1"}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Send(tlsResolverTestQuery(t, "test.example.", 42)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handshake did not start")
	}
	done := make(chan struct{})
	go func() { r.Close(); r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel TLS handshake")
	}
	if err := r.Send(tlsResolverTestQuery(t, "test.example.", 42)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Send after Close: %v", err)
	}
}

func TestDoTLateResponseCannotMatchNextQuery(t *testing.T) {
	firstSeen := make(chan struct{})
	config, dialer := startDoTServer(t, []string{"dot"}, func(ctx context.Context, conn *tls.Conn) {
		first, err := tlsResolverReadFrame(conn)
		if err != nil {
			return
		}
		close(firstSeen)
		second, err := tlsResolverReadFrame(conn)
		if err != nil {
			return
		}
		for i, query := range [][]byte{first, second} {
			response, _ := tlsResolverTestResponse(query)
			var message dnsmessage.Message
			message.Unpack(response)
			message.Answers[0].Body = &dnsmessage.TXTResource{TXT: []string{[]string{"old", "new"}[i]}}
			response, _ = message.Pack()
			tlsResolverWriteFrame(conn, response)
		}
	})
	r, err := NewDoTResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	query := tlsResolverTestQuery(t, "same.example.", 42)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := r.(*DoTResolver).exchange(ctx, bytes.Clone(query)); done <- err }()
	select {
	case <-firstSeen:
	case <-time.After(time.Second):
		t.Fatal("first DoT query did not arrive")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled DoT query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoT request did not cancel")
	}
	if err := r.Send(query); err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(tlsResolverRead(t, r)); err != nil {
		t.Fatal(err)
	}
	if message.ID != 42 || message.Answers[0].Body.(*dnsmessage.TXTResource).TXT[0] != "new" {
		t.Fatal("late DoT response was delivered to a subsequent query")
	}
}

func TestDoTQuestionErrorDoesNotStopNextRequest(t *testing.T) {
	config, dialer := startDoTGateway(t, func(ctx context.Context, query []byte) ([]byte, error) {
		response, err := tlsResolverTestResponse(query)
		if err == nil && query[13] == 'b' {
			response[13] = 'x'
		}
		return response, err
	})
	r, err := NewDoTResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.(*DoTResolver).exchange(ctx, tlsResolverTestQuery(t, "bad.example.", 42)); err == nil {
		t.Fatal("accepted a DoT response with the wrong Question")
	}
	query := tlsResolverTestQuery(t, "good.example.", 43)
	if err := r.Send(query); err != nil {
		t.Fatal(err)
	}
	want, _ := tlsResolverTestResponse(query)
	if !bytes.Equal(tlsResolverRead(t, r), want) {
		t.Fatal("Question mismatch stopped subsequent DoT requests")
	}
}

func TestDoTAuthenticatesEndpointAcrossBootstrap(t *testing.T) {
	serverName := make(chan string, 1)
	config, dialer := startDoTServer(t, []string{"dot"}, func(ctx context.Context, conn *tls.Conn) {
		serverName <- conn.ConnectionState().ServerName
		query, err := tlsResolverReadFrame(conn)
		if err == nil {
			response, _ := tlsResolverTestResponse(query)
			tlsResolverWriteFrame(conn, response)
		}
	})
	r, err := NewDoTResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if err := r.Send(tlsResolverTestQuery(t, "test.example.", 42)); err != nil {
		t.Fatal(err)
	}
	tlsResolverRead(t, r)
	if got := <-serverName; got != "resolver.test" {
		t.Fatalf("bootstrap changed TLS SNI to %q", got)
	}
}

func TestDoTRejectsUntrustedCertificateAndWrongALPN(t *testing.T) {
	for _, mode := range []string{"untrusted", "alpn"} {
		t.Run(mode, func(t *testing.T) {
			protocols := []string{"dot"}
			if mode == "alpn" {
				protocols = []string{"h2"}
			}
			config, dialer := startDoTServer(t, protocols, func(ctx context.Context, conn *tls.Conn) {
				query, err := tlsResolverReadFrame(conn)
				if err == nil {
					response, _ := tlsResolverTestResponse(query)
					tlsResolverWriteFrame(conn, response)
				}
			})
			if mode == "untrusted" {
				config.Certificates = nil
			}
			r, err := NewDoTResolver(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if _, err := r.(*DoTResolver).exchange(ctx, tlsResolverTestQuery(t, "test.example.", 42)); err == nil {
				t.Fatalf("accepted %s DoT endpoint", mode)
			}
		})
	}
}
