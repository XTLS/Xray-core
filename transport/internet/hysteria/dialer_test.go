package hysteria

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/semaphore"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestClientAuthFailure(t *testing.T) {
	for _, failure := range []string{"cancel", "reject"} {
		t.Run(failure, func(t *testing.T) { testClientAuthFailure(t, failure == "reject") })
	}
}

func testClientAuthFailure(t *testing.T, reject bool) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil)
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificate.Certificate},
			PrivateKey:  common.Must2(x509.ParsePKCS8PrivateKey(certificate.PrivateKey)),
		}},
		NextProtos: []string{"h3"},
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	authStarted, firstClosed, acceptDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var connections []*quic.Conn
	var workers sync.WaitGroup
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			mu.Lock()
			connections = append(connections, conn)
			first := len(connections) == 1
			mu.Unlock()
			workers.Add(1)
			go func() {
				defer workers.Done()
				server := &http3.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if first {
						close(authStarted)
						if reject {
							w.WriteHeader(http.StatusForbidden)
							return
						}
						<-r.Context().Done()
						return
					}
					w.WriteHeader(StatusAuthOK)
				})}
				_ = server.ServeQUICConn(conn)
				if first {
					close(firstClosed)
				}
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-acceptDone
		mu.Lock()
		for _, conn := range connections {
			_ = conn.CloseWithError(0, "test cleanup")
		}
		mu.Unlock()
		workers.Wait()
	})
	address, err := xnet.ParseDestination("udp:" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := &client{
		access:     semaphore.New(1),
		dest:       address,
		config:     &Config{Auth: "test"},
		tlsConfig:  &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}},
		quicParams: &internet.QuicParams{DisableChromeParrot: true, Congestion: "reno"},
	}
	callCtx, stop := context.WithCancel(context.Background())
	defer stop()
	result := make(chan error, 1)
	go func() {
		conn, err := c.udp(callCtx)
		if conn != nil {
			_ = conn.Close()
		}
		result <- err
	}()
	select {
	case <-authStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("auth request did not reach the server")
	}
	if !reject {
		stop()
	}
	select {
	case err := <-result:
		if reject {
			if err == nil || !strings.HasSuffix(err.Error(), "auth failed code 403") {
				t.Fatalf("rejected auth: %v", err)
			}
		} else if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled auth: %v", err)
		}
	case <-time.After(time.Second):
		// Release the old implementation's blocked dial before failing.
		mu.Lock()
		_ = connections[0].CloseWithError(0, "test cleanup")
		mu.Unlock()
		<-result
		t.Fatal("failed auth kept waiting for the peer")
	}
	select {
	case <-firstClosed:
	case <-time.After(time.Second):
		t.Fatal("provisional connection survived failed auth")
	}
	if c.conn != nil || c.tr != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatal("failed auth published provisional resources")
	}

	// Failed authentication releases admission without permanently closing this client.
	nextCtx, stopNext := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopNext()
	next, err := c.udp(nextCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	defer c.clean(true)
	connected := c.conn
	canceledCtx, cancelDial := context.WithCancel(context.Background())
	cancelDial()
	<-c.access.Wait()
	err = c.dial(canceledCtx)
	c.access.Signal()
	if !errors.Is(err, context.Canceled) || c.conn != connected {
		t.Fatalf("canceled dial on a ready client: %v", err)
	}
	c.clean(false)
	if c.conn != connected {
		t.Fatal("normal cleanup closed the live replacement connection")
	}
	c.clean(true)
	select {
	case <-connected.Context().Done():
	default:
		t.Fatal("forced cleanup left the replacement connection open")
	}
	if c.conn != nil || c.tr != nil || c.pktConn != nil || c.udpSM != nil {
		t.Fatal("forced cleanup retained client resources")
	}
	for _, dial := range []func(context.Context) (stat.Connection, error){c.tcp, c.udp} {
		conn, err := dial(nextCtx)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil || !strings.HasSuffix(err.Error(), "client is closed") {
			t.Fatalf("forced client dial: %v", err)
		}
	}
}

func TestClientCanceledWaiter(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, cancellation := range []string{"cancel", "deadline"} {
			t.Run(network+"/"+cancellation, func(t *testing.T) {
				c := &client{access: semaphore.New(1)}
				<-c.access.Wait() // Another operation owns the pooled client.
				released := false
				release := func() {
					if !released {
						// Prevent an old implementation from dialing after a test failure.
						c.forced = true
						c.access.Signal()
						released = true
					}
				}
				defer release()
				ctx, cancel := context.WithCancel(context.Background())
				want := context.Canceled
				if cancellation == "deadline" {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				done := make(chan error, 1)
				go func() {
					var err error
					if network == "tcp" {
						_, err = c.tcp(ctx)
					} else {
						_, err = c.udp(ctx)
					}
					done <- err
				}()
				if cancellation == "cancel" {
					cancel()
				}
				select {
				case err := <-done:
					if !errors.Is(err, want) {
						t.Fatalf("canceled waiter: got %v, want %v", err, want)
					}
				case <-time.After(time.Second):
					release()
					<-done
					t.Fatal("canceled dial waited for the busy client")
				}
			})
		}
	}
}
