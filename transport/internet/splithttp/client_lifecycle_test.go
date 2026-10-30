package splithttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOpenStreamCloseCancelsRequest(t *testing.T) {
	for name, streamOne := range map[string]bool{"stream-down": false, "stream-one": true} {
		t.Run(name, func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { conn.Close(); peer.Close() })
			cleanup := make(chan struct{})
			t.Cleanup(func() { close(cleanup) })
			started := make(chan *http.Request, 1)
			client := &DefaultDialerClient{
				transportConfig: &Config{},
				client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					started <- request
					httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: conn})
					select {
					case <-request.Context().Done():
					case <-cleanup:
					}
					return nil, context.Canceled
				})},
			}
			parent, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			var body io.Reader
			if streamOne {
				reader, writer := io.Pipe()
				t.Cleanup(func() { reader.Close(); writer.Close() })
				body = reader
			}
			stream, _, _, err := client.OpenStream(parent, "https://example.test/", "", body, false)
			if err != nil {
				t.Fatal(err)
			}
			request := <-started
			cancel()
			select {
			case <-request.Context().Done():
				t.Fatal("dial context cancellation terminated an open stream")
			default:
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-request.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("closing the stream left its HTTP request running")
			}
		})
	}
}

func TestOpenStreamAbortStress(t *testing.T) {
	cleanup := make(chan struct{})
	started := make(chan struct{})
	var pending atomic.Int32
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2, got %s", request.Proto)
		}
		pending.Add(1)
		defer pending.Add(-1)
		started <- struct{}{}
		select {
		case <-request.Context().Done():
		case <-cleanup:
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	t.Cleanup(func() { close(cleanup) })
	client := &DefaultDialerClient{transportConfig: &Config{}, client: server.Client()}
	const requests = 1000
	for range requests {
		stream, _, _, err := client.OpenStream(context.Background(), server.URL, "", nil, false)
		if err != nil {
			t.Fatal(err)
		}
		<-started
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for pending.Load() != 0 {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("%d/%d aborted HTTP/2 requests remain running; %d TCP connections", pending.Load(), requests, connections.Load())
		}
	}
	if client.IsClosed() {
		t.Fatal("closing individual streams retired the shared HTTP client")
	}
	t.Logf("%d/%d aborted HTTP/2 requests remain running; %d TCP connections", pending.Load(), requests, connections.Load())
}

func TestStreamUpCloseCancelsBothRequests(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	cleanup := make(chan struct{})
	t.Cleanup(func() { close(cleanup) })
	requests := make(chan *http.Request, 2)
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests <- request
			httptrace.ContextClientTrace(request.Context()).GotConn(httptrace.GotConnInfo{Conn: conn})
			select {
			case <-request.Context().Done():
			case <-cleanup:
			}
			return nil, context.Canceled
		})},
	}
	settings := &internet.MemoryStreamConfig{ProtocolSettings: &Config{Mode: "stream-up"}}
	dest := xnet.TCPDestination(xnet.DomainAddress("example.test"), 443)
	key := dialerConf{dest, settings}
	globalDialerAccess.Lock()
	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*XmuxManager)
	}
	globalDialerMap[key] = NewXmuxManager(XmuxConfig{}, func() XmuxConn { return client })
	globalDialerAccess.Unlock()
	t.Cleanup(func() {
		globalDialerAccess.Lock()
		delete(globalDialerMap, key)
		globalDialerAccess.Unlock()
	})
	stream, err := Dial(context.Background(), dest, settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		request := <-requests
		select {
		case <-request.Context().Done():
		case <-time.After(time.Second):
			t.Fatalf("stream-up close left %s request running", request.Method)
		}
	}
}
