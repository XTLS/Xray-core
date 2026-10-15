package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

type doTBackpressureWriter struct {
	*pipe.Writer
	armed   atomic.Bool
	filled  chan struct{}
	blocked chan struct{}
	fill    sync.Once
	block   sync.Once
}

func (w *doTBackpressureWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.armed.Load() && w.Len() > 1 {
		w.block.Do(func() { close(w.blocked) })
	}
	err := w.Writer.WriteMultiBuffer(mb)
	if err == nil && w.armed.Load() {
		w.fill.Do(func() { close(w.filled) })
	}
	return err
}

func TestDoTBlockedCNCWriteCancellationReconnects(t *testing.T) {
	certificate, pem := resolverTestCertificate(t)
	serverCtx, stopServer := context.WithCancel(t.Context())
	var connectionsMu sync.Mutex
	var connections []net.Conn
	var servers sync.WaitGroup
	var dialed atomic.Int32
	ready := make(chan error, 1)
	writer := &doTBackpressureWriter{filled: make(chan struct{}), blocked: make(chan struct{})}
	closeConnections := func() {
		stopServer()
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for _, conn := range connections {
			conn.Close()
		}
	}
	t.Cleanup(func() { closeConnections(); servers.Wait() })
	dialer := &finalmask.Dialer{DialTCPContext: func(ctx context.Context, _ xnet.Destination) (net.Conn, error) {
		uplinkReader, uplinkWriter := pipe.New(pipe.WithSizeLimit(1))
		downlinkReader, downlinkWriter := pipe.New(pipe.WithSizeLimit(1))
		first := dialed.Add(1) == 1
		var input buf.Writer = uplinkWriter
		if first {
			writer.Writer = uplinkWriter
			input = writer
		}
		client := cnc.NewConnection(cnc.ConnectionInputMulti(input), cnc.ConnectionOutputMulti(downlinkReader))
		peer := cnc.NewConnection(cnc.ConnectionInputMulti(downlinkWriter), cnc.ConnectionOutputMulti(uplinkReader))
		connectionsMu.Lock()
		connections = append(connections, client, peer)
		connectionsMu.Unlock()
		servers.Add(1)
		go func() {
			defer servers.Done()
			defer peer.Close()
			conn := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"dot"}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
			err := conn.HandshakeContext(serverCtx)
			if first {
				ready <- err
				// The peer stops consuming uplink only after the real TLS handshake.
				<-serverCtx.Done()
				return
			}
			if err != nil {
				return
			}
			query, err := tlsResolverReadFrame(conn)
			if err == nil {
				response, responseErr := tlsResolverTestResponse(query)
				if responseErr == nil {
					tlsResolverWriteFrame(conn, response)
				}
			}
		}()
		return client, nil
	}}
	resolver, err := NewDoTResolver(&ResolverProto{
		Addr: "resolver.test:853", Bootstrap: "127.0.0.1",
		Certificates: []*xtls.Certificate{{Certificate: pem, Usage: xtls.Certificate_AUTHORITY_VERIFY}},
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	r := resolver.(*DoTResolver)
	// Closing the pipes first makes cleanup release blocked writes even on RED.
	t.Cleanup(func() { closeConnections(); r.Close() })
	connectCtx, stopConnect := context.WithTimeout(t.Context(), 2*time.Second)
	defer stopConnect()
	connection, err := r.connection(connectCtx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("server handshake: %v", err)
		}
	case <-connectCtx.Done():
		t.Fatal("server handshake did not complete")
	}
	writer.armed.Store(true)
	seedCtx, stopSeed := context.WithCancel(t.Context())
	defer stopSeed()
	seedDone := make(chan error, 1)
	seedQuery := tlsResolverTestQuery(t, "seed.example.", 41)
	go func() {
		_, err := r.exchange(seedCtx, seedQuery)
		seedDone <- err
	}()
	select {
	case <-writer.filled:
	case <-time.After(time.Second):
		t.Fatal("first application write did not fill the bounded uplink")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	query := tlsResolverTestQuery(t, "blocked.example.", 42)
	go func() { _, err := r.exchange(ctx, query); done <- err }()
	select {
	case <-writer.blocked:
	case <-ctx.Done():
		t.Fatal("second application write did not reach a full bounded pipe")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("blocked write cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context expiry left the real cnc TLS write blocked")
	}
	select {
	case <-seedDone:
	case <-time.After(time.Second):
		t.Fatal("retired connection left another request waiting")
	}
	select {
	case <-connection.done:
	default:
		t.Fatal("cancelled partial write did not retire the connection")
	}
	if len(connection.writeGate) != 0 {
		t.Fatal("cancelled write retained the writer gate")
	}
	query = tlsResolverTestQuery(t, "reconnect.example.", 43)
	reconnectCtx, stopReconnect := context.WithTimeout(t.Context(), time.Second)
	defer stopReconnect()
	response, err := r.exchange(reconnectCtx, query)
	want, _ := tlsResolverTestResponse(query)
	if err != nil || !bytes.Equal(response, want) {
		t.Fatalf("next exchange did not reconnect: %v", err)
	}
	if dialed.Load() != 2 {
		t.Fatalf("unexpected replay/reconnect count: %d", dialed.Load())
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close retained a read worker after blocked-write cancellation")
	}
}
