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

	"github.com/apernet/quic-go"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/dns/dnsmessage"
)

func startDoQServer(t *testing.T, handle func(context.Context, *quic.Conn, *quic.Stream)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	return startDoQALPNServer(t, []string{"doq"}, handle)
}

func startDoQALPNServer(t *testing.T, protocols []string, handle func(context.Context, *quic.Conn, *quic.Stream)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	certificate, pem := resolverTestCertificate(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: protocols}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	conns := make(map[*quic.Conn]struct{})
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			conns[conn] = struct{}{}
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.CloseWithError(0, "")
				defer func() { mu.Lock(); delete(conns, conn); mu.Unlock() }()
				var streams sync.WaitGroup
				defer streams.Wait()
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					streams.Add(1)
					go func() { defer streams.Done(); handle(ctx, conn, stream) }()
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
			conn.CloseWithError(0, "")
		}
		mu.Unlock()
		workers.Wait()
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := &ResolverProto{
		Type: "quic", Addr: net.JoinHostPort("resolver.test", port), Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Certificate: pem, Usage: xtls.Certificate_AUTHORITY_VERIFY}},
	}
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &xnet.PacketConnWrapper{PacketConn: packet, Dest: &net.UDPAddr{IP: net.ParseIP(dest.Address.String()), Port: int(dest.Port)}}, nil
	}}
	return config, dialer
}

func startDoQGateway(t *testing.T, exchange func(context.Context, []byte) ([]byte, error)) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	return startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		stream.SetDeadline(time.Now().Add(3 * time.Second))
		query, err := tlsResolverReadFrame(stream)
		var extra [1]byte
		if err == nil {
			_, err = io.ReadFull(stream, extra[:])
			if err == io.EOF && len(query) >= 2 && binary.BigEndian.Uint16(query[:2]) == 0 {
				response, err := exchange(ctx, query)
				if err == nil {
					tlsResolverWriteFrame(stream, response)
					stream.Close()
					return
				}
			}
		}
		stream.CancelRead(1)
		stream.CancelWrite(1)
	})
}

func TestDoQZeroIDsIndependentStreamsAndFIN(t *testing.T) {
	queries := make(chan []byte, 2)
	release := make(chan struct{})
	config, dialer := startDoQGateway(t, func(ctx context.Context, query []byte) ([]byte, error) {
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
	r, err := NewDoQResolver(config, dialer)
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
	want, _ := tlsResolverTestResponse(second)
	if !bytes.Equal(tlsResolverRead(t, r), want) {
		t.Fatal("independent DoQ response lost original ID or DNS data")
	}
	close(release)
	want, _ = tlsResolverTestResponse(first)
	if !bytes.Equal(tlsResolverRead(t, r), want) {
		t.Fatal("first DoQ response lost original ID or DNS data")
	}
	for range 2 {
		query := <-queries
		if binary.BigEndian.Uint16(query[:2]) != 0 {
			t.Fatal("nonzero DNS ID sent over DoQ")
		}
	}
	if binary.BigEndian.Uint16(first[:2]) != 99 || binary.BigEndian.Uint16(second[:2]) != 99 {
		t.Fatal("Send modified caller-owned DNS message")
	}
}

func TestDoQClosesConnectionOnProtocolErrors(t *testing.T) {
	for _, mode := range []string{"id", "half-frame", "extra-frame", "missing-fin", "question", "keepalive", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			closed := make(chan error, 1)
			config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
				query, err := tlsResolverReadFrame(stream)
				if err != nil {
					return
				}
				var extra [1]byte
				if _, err := io.ReadFull(stream, extra[:]); err != io.EOF {
					return
				}
				response, _ := tlsResolverTestResponse(query)
				switch mode {
				case "id":
					response[1] = 1
				case "question":
					response[13] = 'x'
				case "keepalive":
					var message dnsmessage.Message
					message.Unpack(response)
					message.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 11}}}
					response, _ = message.Pack()
				}
				switch mode {
				case "half-frame":
					stream.Write([]byte{0, 30, 1})
				case "oversized":
					stream.Write([]byte{0x10, 0x01})
				default:
					tlsResolverWriteFrame(stream, response)
				}
				if mode == "extra-frame" {
					tlsResolverWriteFrame(stream, response)
				}
				if mode != "missing-fin" {
					stream.Close()
				}
				select {
				case <-conn.Context().Done():
					closed <- context.Cause(conn.Context())
				case <-ctx.Done():
				}
			})
			r, err := NewDoQResolver(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()
			if _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "test.example.", 42)); err == nil {
				t.Fatal("accepted DoQ protocol violation")
			}
			select {
			case err := <-closed:
				var applicationError *quic.ApplicationError
				if !errors.As(err, &applicationError) || applicationError.ErrorCode != 2 {
					t.Fatalf("wrong DoQ connection error: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("DoQ protocol error did not close connection")
			}
		})
	}
}

type doQTrackedPacketConn struct {
	net.PacketConn
	closed chan struct{}
	once sync.Once
}

func (c *doQTrackedPacketConn) Close() error {
	var err error
	c.once.Do(func() { err = c.PacketConn.Close(); close(c.closed) })
	return err
}

func TestDoQRejectsTLSIdentityAndReleasesSocket(t *testing.T) {
	config, dialer := startDoQGateway(t, func(ctx context.Context, query []byte) ([]byte, error) { return tlsResolverTestResponse(query) })
	config.ServerName = "wrong.example"
	dial := dialer.DialUDPContext
	opened := make(chan *doQTrackedPacketConn, 1)
	dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		conn, err := dial(ctx, dest)
		if err != nil {
			return nil, err
		}
		wrapper := conn.(*xnet.PacketConnWrapper)
		packet := &doQTrackedPacketConn{PacketConn: wrapper.PacketConn, closed: make(chan struct{})}
		wrapper.PacketConn = packet
		opened <- packet
		return wrapper, nil
	}
	r, err := NewDoQResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "test.example.", 42)); err == nil {
		t.Fatal("accepted wrong DoQ TLS identity")
	}
	select {
	case packet := <-opened:
		select {
		case <-packet.closed:
		case <-time.After(time.Second):
			t.Fatal("failed QUIC handshake leaked PacketConn")
		}
	case <-time.After(time.Second):
		t.Fatal("QUIC dial was not attempted")
	}
}

func TestDoQCancellationStopsStreamAndNextQueryWorks(t *testing.T) {
	started := make(chan struct{}, 1)
	cancelled := make(chan error, 1)
	var count atomic.Int32
	config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		query, err := tlsResolverReadFrame(stream)
		if err != nil {
			return
		}
		var extra [1]byte
		if _, err := io.ReadFull(stream, extra[:]); err != io.EOF {
			return
		}
		if count.Add(1) == 1 {
			started <- struct{}{}
			select {
			case <-stream.Context().Done():
				cancelled <- context.Cause(stream.Context())
			case <-ctx.Done():
			}
			return
		}
		response, _ := tlsResolverTestResponse(query)
		tlsResolverWriteFrame(stream, response)
		stream.Close()
	})
	r, err := NewDoQResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "first.example.", 42)); done <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DoQ query did not reach server")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled query: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DoQ stream did not stop on cancellation")
	}
	select {
	case err := <-cancelled:
		var streamError *quic.StreamError
		if !errors.As(err, &streamError) || streamError.ErrorCode != 3 {
			t.Fatalf("cancellation did not use DOQ_REQUEST_CANCELLED: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive stream cancellation")
	}
	query := tlsResolverTestQuery(t, "second.example.", 43)
	if err := r.Send(query); err != nil {
		t.Fatal(err)
	}
	want, _ := tlsResolverTestResponse(query)
	if !bytes.Equal(tlsResolverRead(t, r), want) {
		t.Fatal("request cancellation broke subsequent query")
	}
}

func TestDoQRejectsPort53AndNonPacketDial(t *testing.T) {
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		client, server := net.Pipe()
		server.Close()
		return client, nil
	}}
	if r, err := NewDoQResolver(&ResolverProto{Addr: "127.0.0.1:53"}, dialer); err == nil {
		r.Close()
		t.Fatal("DoQ allowed UDP port 53")
	}
	r, err := NewDoQResolver(&ResolverProto{Addr: "127.0.0.1:853"}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "test.example.", 42)); err == nil {
		t.Fatal("DoQ accepted a dial result without PacketConnWrapper")
	}
}

func TestDoQAuthenticatesEndpointAndNegotiatesDoQ(t *testing.T) {
	state := make(chan tls.ConnectionState, 1)
	config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		state <- conn.ConnectionState().TLS
		query, err := tlsResolverReadFrame(stream)
		if err != nil {
			return
		}
		var extra [1]byte
		if _, err := io.ReadFull(stream, extra[:]); err != io.EOF {
			return
		}
		response, _ := tlsResolverTestResponse(query)
		tlsResolverWriteFrame(stream, response)
		stream.Close()
	})
	r, err := NewDoQResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if err := r.Send(tlsResolverTestQuery(t, "test.example.", 42)); err != nil {
		t.Fatal(err)
	}
	tlsResolverRead(t, r)
	got := <-state
	if got.ServerName != "resolver.test" || got.NegotiatedProtocol != "doq" {
		t.Fatalf("DoQ bootstrap/ALPN changed TLS identity: SNI %q, ALPN %q", got.ServerName, got.NegotiatedProtocol)
	}
}

func TestDoQReconnectsWithoutReplayAfterPeerClose(t *testing.T) {
	var count atomic.Int32
	config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		query, err := tlsResolverReadFrame(stream)
		if err != nil {
			return
		}
		var extra [1]byte
		if _, err := io.ReadFull(stream, extra[:]); err != io.EOF {
			return
		}
		if count.Add(1) == 1 {
			conn.CloseWithError(0, "restart")
			return
		}
		response, _ := tlsResolverTestResponse(query)
		tlsResolverWriteFrame(stream, response)
		stream.Close()
	})
	r, err := NewDoQResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	query := tlsResolverTestQuery(t, "test.example.", 42)
	if _, err := r.(*DoQResolver).exchange(ctx, bytes.Clone(query)); err == nil {
		t.Fatal("peer close was accepted as a DNS response")
	}
	response, err := r.(*DoQResolver).exchange(ctx, bytes.Clone(query))
	want, _ := tlsResolverTestResponse(query)
	if err != nil || !bytes.Equal(response, want) {
		t.Fatalf("subsequent DoQ request did not reconnect: %v", err)
	}
	if count.Load() != 2 {
		t.Fatal("DoQ automatically replayed a submitted query")
	}
}

func TestDoQCloseActiveQueryReleasesSocketAndRead(t *testing.T) {
	started := make(chan struct{}, 1)
	config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		if _, err := tlsResolverReadFrame(stream); err != nil {
			return
		}
		started <- struct{}{}
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
		}
	})
	dial := dialer.DialUDPContext
	opened := make(chan *doQTrackedPacketConn, 1)
	dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		conn, err := dial(ctx, dest)
		if err != nil {
			return nil, err
		}
		wrapper := conn.(*xnet.PacketConnWrapper)
		packet := &doQTrackedPacketConn{PacketConn: wrapper.PacketConn, closed: make(chan struct{})}
		wrapper.PacketConn = packet
		opened <- packet
		return wrapper, nil
	}
	r, err := NewDoQResolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	if err := r.Send(tlsResolverTestQuery(t, "test.example.", 42)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("DoQ query did not arrive")
	}
	packet := <-opened
	read := make(chan error, 1)
	go func() { _, err := r.Read(make([]byte, 4096)); read <- err }()
	var closing sync.WaitGroup
	for range 3 {
		closing.Add(1)
		go func() { defer closing.Done(); r.Close() }()
	}
	done := make(chan struct{})
	go func() { closing.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop active DoQ exchange")
	}
	select {
	case <-packet.closed:
	default:
		t.Fatal("DoQ Close left UDP socket open")
	}
	select {
	case err := <-read:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("Read after Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock resolver Read")
	}
}

func TestDoQRejectsTCPKeepaliveBeforeDial(t *testing.T) {
	var dialed atomic.Bool
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected dial")
	}}
	r, err := NewDoQResolver(&ResolverProto{Addr: "resolver.test:853", Bootstrap: "127.0.0.1"}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	var query dnsmessage.Message
	query.Unpack(tlsResolverTestQuery(t, "test.example.", 42))
	query.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 11}}}
	p, _ := query.Pack()
	if _, err := r.(*DoQResolver).exchange(t.Context(), p); err == nil || dialed.Load() {
		t.Fatal("DoQ sent a forbidden TCP keepalive option")
	}
}

func TestDoQRejectsWrongALPNAndUntrustedCertificate(t *testing.T) {
	for _, mode := range []string{"alpn", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			protocols := []string{"doq"}
			if mode == "alpn" {
				protocols = []string{"h3"}
			}
			config, dialer := startDoQALPNServer(t, protocols, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
				query, err := tlsResolverReadFrame(stream)
				if err == nil {
					response, _ := tlsResolverTestResponse(query)
					tlsResolverWriteFrame(stream, response)
					stream.Close()
				}
			})
			if mode == "untrusted" {
				config.Certificates = nil
			}
			r, err := NewDoQResolver(config, dialer)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(r.Close)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "test.example.", 42)); err == nil {
				t.Fatalf("accepted %s DoQ endpoint", mode)
			}
		})
	}
}

func TestDoQDNSFailureDoesNotCloseConnection(t *testing.T) {
	connections := make(chan *quic.Conn, 2)
	var count atomic.Int32
	config, dialer := startDoQServer(t, func(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
		query, err := tlsResolverReadFrame(stream)
		if err != nil { return }
		var extra [1]byte
		if _, err := io.ReadFull(stream, extra[:]); err != io.EOF { return }
		connections <- conn
		response, _ := tlsResolverTestResponse(query)
		if count.Add(1) == 1 {
			var message dnsmessage.Message
			message.Unpack(response)
			message.RCode = dnsmessage.RCodeServerFailure
			message.Answers = nil
			response, _ = message.Pack()
		}
		tlsResolverWriteFrame(stream, response)
		stream.Close()
	})
	r, err := NewDoQResolver(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(r.Close)
	if err := r.Send(tlsResolverTestQuery(t, "failed.example.", 99)); err != nil { t.Fatal(err) }
	var failed dnsmessage.Message
	if err := failed.Unpack(tlsResolverRead(t, r)); err != nil { t.Fatal(err) }
	if failed.ID != 99 || failed.RCode != dnsmessage.RCodeServerFailure { t.Fatal("DoQ discarded or changed the DNS failure response") }
	query := tlsResolverTestQuery(t, "next.example.", 100)
	if err := r.Send(query); err != nil { t.Fatal(err) }
	want, _ := tlsResolverTestResponse(query)
	if !bytes.Equal(tlsResolverRead(t, r), want) { t.Fatal("subsequent DNS query failed") }
	first, second := <-connections, <-connections
	if first != second { t.Fatal("ordinary DNS failure closed the shared DoQ connection") }
}

type doQVirtualPeerConn struct {
	net.Conn
	closed chan struct{}
	once sync.Once
}

func (c *doQVirtualPeerConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *doQVirtualPeerConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); close(c.closed) })
	return err
}

func TestDoQProductionFakePacketConnVirtualPeer(t *testing.T) {
	config, _ := startDoQGateway(t, func(ctx context.Context, query []byte) ([]byte, error) { return tlsResolverTestResponse(query) })
	opened := make(chan *doQVirtualPeerConn, 1)
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "udp", dest.NetAddr())
		if err != nil { return nil, err }
		virtual := &doQVirtualPeerConn{Conn: conn, closed: make(chan struct{})}
		opened <- virtual
		return &xnet.PacketConnWrapper{PacketConn: &internet.FakePacketConn{Conn: virtual}, Dest: &net.UDPAddr{IP: net.IPv4zero}}, nil
	}}
	r, err := NewDoQResolver(config, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(r.Close)
	query := tlsResolverTestQuery(t, "virtual.example.", 42)
	if err := r.Send(query); err != nil { t.Fatal(err) }
	want, _ := tlsResolverTestResponse(query)
	if !bytes.Equal(tlsResolverRead(t, r), want) { t.Fatal("production FakePacketConn lost DoQ payload or transaction ID") }
	virtual := <-opened
	r.Close()
	select {
	case <-virtual.closed:
	default: t.Fatal("DoQ Close left virtual outbound connection open")
	}
}

func TestDoQRejectsZeroPortOnRealPacketConn(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	tracked := &doQTrackedPacketConn{PacketConn: packet, closed: make(chan struct{})}
	t.Cleanup(func() { tracked.Close() })
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		return &xnet.PacketConnWrapper{PacketConn: tracked, Dest: &net.UDPAddr{IP: net.IPv4zero}}, nil
	}}
	r, err := NewDoQResolver(&ResolverProto{Addr: "resolver.test:853", Bootstrap: "127.0.0.1"}, dialer)
	if err != nil { t.Fatal(err) }
	t.Cleanup(r.Close)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := r.(*DoQResolver).exchange(ctx, tlsResolverTestQuery(t, "bad-peer.example.", 42)); err == nil { t.Fatal("real UDP socket accepted a zero-port peer") }
	select {
	case <-tracked.closed:
	default: t.Fatal("invalid UDP peer leaked socket")
	}
}
