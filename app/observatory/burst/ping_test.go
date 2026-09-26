package burst

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

const testWaitTimeout = 5 * time.Second

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	reader io.Reader
	reads  atomic.Int32
	closed atomic.Bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.reader.Read(p)
}

func (b *trackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func setTaggedDialer(t *testing.T, dialer tagged.DialFunc) {
	t.Helper()
	originalDialer := tagged.Dialer
	tagged.Dialer = dialer
	t.Cleanup(func() { tagged.Dialer = originalDialer })
}

func waitForSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testWaitTimeout):
		t.Fatal(message)
	}
}

func TestMeasureDelayCanceledBeforeRequest(t *testing.T) {
	var dialCalled atomic.Bool
	setTaggedDialer(t, func(context.Context, routing.Dispatcher, coreNet.Destination, string) (coreNet.Conn, error) {
		dialCalled.Store(true)
		return nil, errors.New("unexpected dial")
	})
	client := newPingClient(nil, "http://example.com", time.Minute, "test")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.MeasureDelay(ctx, http.MethodHead)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("MeasureDelay() error = %v, want context.Canceled", err)
	}
	if dialCalled.Load() {
		t.Fatal("dialer was called for an already canceled request")
	}
}

func TestMeasureDelayCancelsTaggedDial(t *testing.T) {
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	releaseDial := make(chan struct{})
	t.Cleanup(func() { close(releaseDial) })
	setTaggedDialer(t, func(ctx context.Context, _ routing.Dispatcher, _ coreNet.Destination, _ string) (coreNet.Conn, error) {
		close(dialStarted)
		select {
		case <-ctx.Done():
			close(dialCanceled)
			return nil, ctx.Err()
		case <-releaseDial:
			return nil, errors.New("test released dial")
		}
	})

	client := newPingClient(nil, "http://example.com", time.Minute, "test")
	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	go func() {
		_, err := client.MeasureDelay(ctx, http.MethodHead)
		requestDone <- err
	}()

	waitForSignal(t, dialStarted, "dial did not start")
	cancel()
	waitForSignal(t, dialCanceled, "canceling the request did not cancel the tagged dial")
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("MeasureDelay() error = %v, want context.Canceled", err)
		}
	case <-time.After(testWaitTimeout):
		t.Fatal("MeasureDelay() did not return after cancellation")
	}
}

func TestMeasureDelayCancelsResponseRead(t *testing.T) {
	readStarted := make(chan struct{})
	bodyClosed := make(chan struct{})
	client := &pingClient{
		destination: "http://example.com",
		httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: &blockingBody{
					ctx:         req.Context(),
					readStarted: readStarted,
					closed:      bodyClosed,
				},
			}, nil
		})},
	}
	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	go func() {
		_, err := client.MeasureDelay(ctx, http.MethodGet)
		requestDone <- err
	}()

	waitForSignal(t, readStarted, "response body read did not start")
	cancel()
	select {
	case err := <-requestDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("MeasureDelay() error = %v, want context.Canceled", err)
		}
	case <-time.After(testWaitTimeout):
		t.Fatal("MeasureDelay() did not return after canceling a response body read")
	}
	waitForSignal(t, bodyClosed, "response body was not closed after cancellation")
}

type blockingBody struct {
	ctx         context.Context
	readStarted chan<- struct{}
	closed      chan<- struct{}
}

func (b *blockingBody) Read([]byte) (int, error) {
	close(b.readStarted)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *blockingBody) Close() error {
	close(b.closed)
	return nil
}

func TestMeasureDelayClosesBodyOnReadError(t *testing.T) {
	readErr := errors.New("response read failed")
	body := &trackingBody{reader: errorReader{err: readErr}}
	client := pingClient{
		destination: "http://example.com",
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
		})},
	}

	_, err := client.MeasureDelay(context.Background(), http.MethodGet)
	if !errors.Is(err, readErr) {
		t.Fatalf("MeasureDelay() error = %v, want %v", err, readErr)
	}
	if !body.closed.Load() {
		t.Fatal("response body was not closed after a read error")
	}
}

type errorReader struct {
	err error
}

func (r errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func TestMeasureDelayBodyHandling(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		wantReads bool
	}{
		{name: "HEAD closes without reading", method: http.MethodHead, wantReads: false},
		{name: "GET drains and closes", method: http.MethodGet, wantReads: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &trackingBody{reader: strings.NewReader("response")}
			client := pingClient{
				destination: "http://example.com/check",
				httpClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Method != test.method {
						t.Errorf("request method = %q, want %q", req.Method, test.method)
					}
					if req.URL.String() != "http://example.com/check" {
						t.Errorf("request URL = %q, want destination URL", req.URL)
					}
					if req.Header.Get("User-Agent") == "" {
						t.Error("default request headers were not applied")
					}
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
				})},
			}

			if _, err := client.MeasureDelay(context.Background(), test.method); err != nil {
				t.Fatalf("MeasureDelay() error = %v", err)
			}
			if gotReads := body.reads.Load() > 0; gotReads != test.wantReads {
				t.Errorf("response body read = %v, want %v", gotReads, test.wantReads)
			}
			if !body.closed.Load() {
				t.Error("response body was not closed")
			}
		})
	}
}

func TestMeasureDelayPreservesClientTimeout(t *testing.T) {
	dialCanceled := make(chan struct{})
	setTaggedDialer(t, func(ctx context.Context, _ routing.Dispatcher, _ coreNet.Destination, _ string) (coreNet.Conn, error) {
		<-ctx.Done()
		close(dialCanceled)
		return nil, ctx.Err()
	})

	client := newPingClient(nil, "http://example.com", 50*time.Millisecond, "test")
	_, err := client.MeasureDelay(context.Background(), http.MethodHead)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("MeasureDelay() error = %v, want context.DeadlineExceeded", err)
	}
	waitForSignal(t, dialCanceled, "client timeout did not cancel the tagged dial")
}

func TestDoCheckCancelsInFlightRequest(t *testing.T) {
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	setTaggedDialer(t, func(ctx context.Context, _ routing.Dispatcher, _ coreNet.Destination, _ string) (coreNet.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		close(dialCanceled)
		return nil, ctx.Err()
	})

	healthPing := &HealthPing{
		ctx: context.Background(),
		Settings: &HealthPingSettings{
			Destination: "http://example.com",
			Timeout:     time.Minute,
			HttpMethod:  http.MethodHead,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	checkDone := make(chan struct{})
	go func() {
		healthPing.doCheck(ctx, []string{"test"}, 0, 1)
		close(checkDone)
	}()

	waitForSignal(t, dialStarted, "health check dial did not start")
	cancel()
	waitForSignal(t, dialCanceled, "canceling the health check did not cancel its tagged dial")
	waitForSignal(t, checkDone, "health check did not return after cancellation")
}
