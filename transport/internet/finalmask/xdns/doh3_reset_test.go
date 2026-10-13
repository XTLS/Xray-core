package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type doH3ResetEvent struct {
	upstreamAlive bool
}

func startDoH3ResetTestGateway(t *testing.T, handler http.Handler, resetStreams int32, resets chan<- doH3ResetEvent) (*ResolverProto, *finalmask.Dialer) {
	t.Helper()
	cert, ca := resolverTestCertificate(t)
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transport := &quic.Transport{Conn: packetConn}
	listener, err := transport.Listen(http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}), &quic.Config{Allow0RTT: false})
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		t.Fatal(err)
	}
	var streams atomic.Int32
	var serverConn atomic.Pointer[quic.Conn]
	server := &http3.Server{
		Handler: handler,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			serverConn.Store(conn)
			return ctx
		},
		StreamDispatcher: func(_ http3.FrameType, stream *quic.Stream, _ error) (bool, error) {
			if streams.Add(1) <= resetStreams {
				conn := serverConn.Load()
				alive := conn != nil && conn.Context().Err() == nil
				stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
				stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
				resets <- doH3ResetEvent{upstreamAlive: alive}
				return true, nil
			}
			return false, nil
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeListener(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = transport.Close()
		_ = packetConn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("H3 reset gateway did not exit")
		}
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	config := &ResolverProto{
		Type: "https+h3", Addr: "https+h3://resolver.test:" + port + "/dns-query", Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Usage: xtls.Certificate_AUTHORITY_VERIFY, Certificate: ca}},
	}
	dialer := &finalmask.Dialer{DialUDPContext: func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if dest.Network != xnet.Network_UDP || dest.Address.String() != "127.0.0.1" || strconv.Itoa(int(dest.Port)) != port {
			t.Errorf("wrong H3 bootstrap destination: %v", dest)
		}
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		return &xnet.PacketConnWrapper{PacketConn: conn, Dest: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(dest.Port)}}, nil
	}}
	return config, dialer
}

func TestDoH3RetiresConnectionAfterRequestStreamReset(t *testing.T) {
	const resetCount = 3
	resets := make(chan doH3ResetEvent, resetCount)
	queries := make(chan []byte, 1)
	config, dialer := startDoH3ResetTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read healthy H3 request: %v", err)
			return
		}
		queries <- bytes.Clone(body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(httpTestResponse(t, body))
	}), resetCount, resets)

	var dials atomic.Int32
	created := make(chan *httpTestTrackedPacketConn, resetCount+1)
	connections := make([]*httpTestTrackedPacketConn, 0, resetCount+1)
	dial := dialer.DialUDPContext
	dialer.DialUDPContext = func(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
		conn, err := dial(ctx, dest)
		if err != nil {
			return nil, err
		}
		wrapper := conn.(*xnet.PacketConnWrapper)
		tracked := &httpTestTrackedPacketConn{PacketConn: wrapper.PacketConn, closed: make(chan struct{})}
		wrapper.PacketConn = tracked
		created <- tracked
		dials.Add(1)
		return wrapper, nil
	}

	resolver, err := NewDoH3Resolver(config, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	type exchangeResult struct {
		err    error
		ctxErr error
	}
	exchanges := make(chan exchangeResult, resetCount+1)
	rr := resolver.(*requestResolver)
	exchange := rr.exchange
	rr.exchange = func(ctx context.Context, query []byte) ([]byte, error) {
		response, err := exchange(ctx, query)
		exchanges <- exchangeResult{err: err, ctxErr: ctx.Err()}
		return response, err
	}

	for i := 0; i < resetCount; i++ {
		query := httpTestQuery(t, uint16(90+i), "reset-"+strconv.Itoa(i)+".example.")
		if err := resolver.Send(query); err != nil {
			t.Fatal(err)
		}
		select {
		case conn := <-created:
			connections = append(connections, conn)
		case <-time.After(3 * time.Second):
			t.Fatalf("request %d did not create an H3 PacketConn", i+1)
		}
		select {
		case event := <-resets:
			if !event.upstreamAlive {
				t.Fatalf("upstream QUIC connection was already closed before reset %d", i+1)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("H3 request stream %d was not reset", i+1)
		}
		select {
		case result := <-exchanges:
			if result.err == nil || result.ctxErr != nil {
				t.Fatalf("reset exchange %d did not finish with an uncanceled request error: err=%v context=%v", i+1, result.err, result.ctxErr)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("reset exchange %d did not return", i+1)
		}
	}

	good := httpTestQuery(t, 99, "recovered.example.")
	if err := resolver.Send(good); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-exchanges:
		if result.err != nil || result.ctxErr != nil {
			t.Fatalf("healthy exchange failed: err=%v context=%v", result.err, result.ctxErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("healthy exchange did not return")
	}
	select {
	case conn := <-created:
		connections = append(connections, conn)
	case <-time.After(3 * time.Second):
		t.Fatal("healthy request did not create a replacement H3 PacketConn")
	}
	if got := httpTestRead(t, resolver); !bytes.Equal(got, httpTestResponse(t, good)) {
		t.Fatal("resolver did not recover after H3 stream resets")
	}
	select {
	case got := <-queries:
		expectedWire := bytes.Clone(good)
		expectedWire[0], expectedWire[1] = 0, 0
		if !bytes.Equal(got, expectedWire) {
			t.Fatal("healthy request carried a different DNS query")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("healthy request body was not observed")
	}
	if got := dials.Load(); got != resetCount+1 {
		t.Fatalf("expected one dial per submitted request, got %d dials", got)
	}
	for i, conn := range connections[:resetCount] {
		select {
		case <-conn.closed:
		case <-time.After(3 * time.Second):
			t.Fatalf("retired H3 PacketConn %d remained open until resolver.Close", i+1)
		}
	}
}
