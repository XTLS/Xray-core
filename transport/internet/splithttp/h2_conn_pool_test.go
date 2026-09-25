package splithttp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	stdnet "net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
)

func TestCoalescingHTTP2PoolColdStart(t *testing.T) {
	var dials atomic.Int32
	transport := newPipeHTTP2Transport(t, &dials, &http2.Server{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	client := &http.Client{Transport: transport}

	const requests = 64
	start := make(chan struct{})
	errs := make(chan error, requests)
	for range requests {
		go func() {
			<-start
			response, err := client.Get("https://xray.test/")
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			errs <- err
		}()
	}
	close(start)

	for range requests {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("physical dials = %d, want 1", got)
	}
}

func TestCoalescingHTTP2PoolSharesInFlightDial(t *testing.T) {
	var dials atomic.Int32
	dialStarted := make(chan struct{})
	transport := newHTTP2Transport(func(ctx context.Context) (xnet.Conn, error) {
		if dials.Add(1) == 1 {
			close(dialStarted)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}, time.Minute, 0)
	pool := transport.ConnPool

	ctx, cancel := context.WithCancel(context.Background())
	const requests = 64
	start := make(chan struct{})
	errs := make(chan error, requests)
	for range requests {
		go func() {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://xray.test/", nil)
			if err != nil {
				errs <- err
				return
			}
			<-start
			_, err = pool.GetClientConn(request, "xray.test:443")
			errs <- err
		}()
	}
	close(start)

	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	time.Sleep(50 * time.Millisecond)
	if got := dials.Load(); got != 1 {
		t.Fatalf("concurrent in-flight dials = %d, want 1", got)
	}
	cancel()
	for range requests {
		if err := <-errs; err == nil {
			t.Fatal("GetClientConn unexpectedly succeeded")
		}
	}
}

func TestDefaultDialerClientCancelsStalledHTTP2Dial(t *testing.T) {
	handshakeStarted := make(chan struct{})
	peerClosed := make(chan struct{})
	transport := newHTTP2Transport(func(context.Context) (xnet.Conn, error) {
		clientConn, serverConn := stdnet.Pipe()
		go func() {
			defer serverConn.Close()
			buffer := make([]byte, 1)
			_, _ = serverConn.Read(buffer)
			close(handshakeStarted)
			_, _ = io.Copy(io.Discard, serverConn)
			close(peerClosed)
		}()
		return tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true}), nil
	}, time.Minute, 0)
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		httpVersion:     "2",
	}

	ctx, cancel := context.WithCancel(context.Background())
	openDone := make(chan struct{})
	go func() {
		stream, _, _, _ := client.OpenStream(ctx, "https://xray.test/", "session", nil, false)
		if stream != nil {
			_ = stream.Close()
		}
		close(openDone)
	}()

	select {
	case <-handshakeStarted:
	case <-time.After(time.Second):
		t.Fatal("TLS handshake did not start")
	}
	cancel()
	select {
	case <-peerClosed:
	case <-time.After(time.Second):
		t.Fatal("stalled TLS connection was not closed with the caller")
	}
	select {
	case <-openDone:
	case <-time.After(time.Second):
		t.Fatal("OpenStream did not return after cancellation")
	}
}

func TestDefaultDialerClientKeepsEstablishedHTTP2StreamAfterCallerCancellation(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseResponse := make(chan struct{})
	var dials atomic.Int32
	transport := newPipeHTTP2Transport(t, &dials, &http2.Server{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseResponse
		_, _ = io.WriteString(w, "response")
	}))
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		httpVersion:     "2",
	}

	ctx, cancel := context.WithCancel(context.Background())
	stream, _, _, err := client.OpenStream(ctx, "https://xray.test/", "session", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	waitForStartedRequest(t, requestStarted)
	cancel()
	close(releaseResponse)

	readDone := make(chan struct {
		body string
		err  error
	}, 1)
	go func() {
		body, err := io.ReadAll(stream)
		readDone <- struct {
			body string
			err  error
		}{string(body), err}
	}()
	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.body != "response" {
			t.Fatalf("response body = %q, want %q", result.body, "response")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("established stream stopped after caller cancellation")
	}
}

func TestCoalescingHTTP2PoolRetriesCanceledLeader(t *testing.T) {
	var dials atomic.Int32
	firstDialStarted := make(chan struct{})
	var serverConns sync.WaitGroup
	transport := newHTTP2Transport(func(ctx context.Context) (xnet.Conn, error) {
		if dials.Add(1) == 1 {
			close(firstDialStarted)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		clientConn, serverConn := stdnet.Pipe()
		serverConns.Add(1)
		go func() {
			defer serverConns.Done()
			(&http2.Server{}).ServeConn(serverConn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})})
		}()
		return clientConn, nil
	}, time.Minute, 0)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderRequest, err := http.NewRequestWithContext(leaderCtx, http.MethodGet, "https://xray.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	leaderDone := make(chan error, 1)
	go func() {
		_, err := transport.ConnPool.GetClientConn(leaderRequest, "xray.test:443")
		leaderDone <- err
	}()
	<-firstDialStarted

	const waiters = 64
	waiterStart := make(chan struct{})
	waiterReady := sync.WaitGroup{}
	waiterReady.Add(waiters)
	waiterDone := make(chan *http2.ClientConn, waiters)
	for range waiters {
		go func() {
			request, err := http.NewRequest(http.MethodGet, "https://xray.test/", nil)
			if err != nil {
				waiterReady.Done()
				waiterDone <- nil
				return
			}
			waiterReady.Done()
			<-waiterStart
			conn, _ := transport.ConnPool.GetClientConn(request, "xray.test:443")
			waiterDone <- conn
		}()
	}
	waiterReady.Wait()
	close(waiterStart)
	cancelLeader()

	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error = %v, want context.Canceled", err)
	}
	var sharedConn *http2.ClientConn
	for range waiters {
		select {
		case conn := <-waiterDone:
			if conn == nil {
				t.Fatal("live waiter did not retry the canceled dial")
			}
			sharedConn = conn
		case <-time.After(3 * time.Second):
			t.Fatal("live waiter did not finish its retry")
		}
	}
	_ = sharedConn.Close()
	serverConns.Wait()
	if got := dials.Load(); got != 2 {
		t.Fatalf("physical dials = %d, want 2", got)
	}
}

func TestCoalescingHTTP2PoolOpensConnectionAtPeerStreamLimit(t *testing.T) {
	var dials atomic.Int32
	requestStarted := make(chan struct{}, 2)
	release := make(chan struct{})
	server := &http2.Server{MaxConcurrentStreams: 1}
	transport := newPipeHTTP2Transport(t, &dials, server, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/prime" {
			w.WriteHeader(http.StatusOK)
			return
		}
		requestStarted <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	client := &http.Client{Transport: transport}

	response, err := client.Get("https://xray.test/prime")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	request := func(path string) <-chan error {
		done := make(chan error, 1)
		go func() {
			response, err := client.Get("https://xray.test" + path)
			if err == nil {
				response.Body.Close()
			}
			done <- err
		}()
		return done
	}

	first := request("/first")
	waitForStartedRequest(t, requestStarted)
	second := request("/second")
	waitForStartedRequest(t, requestStarted)
	if got := dials.Load(); got != 2 {
		t.Fatalf("physical dials = %d, want 2 after peer stream limit is reached", got)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}

func newPipeHTTP2Transport(t *testing.T, dials *atomic.Int32, server *http2.Server, handler http.Handler) *http2.Transport {
	t.Helper()
	var serverConns sync.WaitGroup
	var clientConnsMu sync.Mutex
	var clientConns []stdnet.Conn
	t.Cleanup(func() {
		clientConnsMu.Lock()
		for _, conn := range clientConns {
			_ = conn.Close()
		}
		clientConnsMu.Unlock()
		serverConns.Wait()
	})
	return newHTTP2Transport(func(context.Context) (xnet.Conn, error) {
		dials.Add(1)
		clientConn, serverConn := stdnet.Pipe()
		clientConnsMu.Lock()
		clientConns = append(clientConns, clientConn)
		clientConnsMu.Unlock()
		serverConns.Add(1)
		go func() {
			defer serverConns.Done()
			server.ServeConn(serverConn, &http2.ServeConnOpts{Handler: handler})
		}()
		return clientConn, nil
	}, time.Minute, 0)
}

func waitForStartedRequest(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach the HTTP/2 server")
	}
}
