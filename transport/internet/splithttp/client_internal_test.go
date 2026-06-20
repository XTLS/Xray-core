package splithttp

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

type closeTrackingTransport struct {
	mu                    sync.Mutex
	closeIdleCalls        int
	closeCallsAtRoundTrip []int
}

func (t *closeTrackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		io.Copy(io.Discard, req.Body)
		req.Body.Close()
	}

	t.mu.Lock()
	t.closeCallsAtRoundTrip = append(t.closeCallsAtRoundTrip, t.closeIdleCalls)
	t.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (t *closeTrackingTransport) CloseIdleConnections() {
	t.mu.Lock()
	t.closeIdleCalls++
	t.mu.Unlock()
}

func (t *closeTrackingTransport) CloseIdleCallCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeIdleCalls
}

func (t *closeTrackingTransport) CloseCallsAtRoundTrip(index int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCallsAtRoundTrip[index]
}

func TestDefaultDialerClientPostPacketDoesNotCloseIdleConnectionOnFirstH2Post(t *testing.T) {
	transport := &closeTrackingTransport{}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		httpVersion:     "2",
	}

	if err := client.PostPacket(context.Background(), "http://example.com/upload", "session", "0", testPacketPayload()); err != nil {
		t.Fatal(err)
	}

	if got := transport.CloseIdleCallCount(); got != 0 {
		t.Fatalf("expected first H2 packet-up POST not to close idle connections, got %d calls", got)
	}
	if got := transport.CloseCallsAtRoundTrip(0); got != 0 {
		t.Fatalf("expected no idle close before first RoundTrip, got %d calls", got)
	}
	if client.lastPacketUp.IsZero() {
		t.Fatal("expected lastPacketUp to be recorded")
	}
}

func TestDefaultDialerClientPostPacketClosesIdleConnectionBeforeStaleH2Post(t *testing.T) {
	transport := &closeTrackingTransport{}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		httpVersion:     "2",
		lastPacketUp:    time.Now().Add(-packetUpIdleConnectionStaleDuration - time.Second),
	}

	if err := client.PostPacket(context.Background(), "http://example.com/upload", "session", "1", testPacketPayload()); err != nil {
		t.Fatal(err)
	}

	if got := transport.CloseIdleCallCount(); got != 1 {
		t.Fatalf("expected stale H2 packet-up POST to close idle connections once, got %d calls", got)
	}
	if got := transport.CloseCallsAtRoundTrip(0); got != 1 {
		t.Fatalf("expected idle connections to be closed before RoundTrip, got %d calls before RoundTrip", got)
	}
}

func TestDefaultDialerClientPostPacketDoesNotCloseIdleConnectionForH1(t *testing.T) {
	transport := &closeTrackingTransport{}
	client := &DefaultDialerClient{
		transportConfig: &Config{},
		client:          &http.Client{Transport: transport},
		httpVersion:     "1.1",
		lastPacketUp:    time.Now().Add(-packetUpIdleConnectionStaleDuration - time.Second),
		uploadRawPool:   &sync.Pool{},
		dialUploadConn: func(context.Context) (stdnet.Conn, error) {
			return &writeOnlyConn{}, nil
		},
	}

	if err := client.PostPacket(context.Background(), "http://example.com/upload", "session", "2", testPacketPayload()); err != nil {
		t.Fatal(err)
	}

	if got := transport.CloseIdleCallCount(); got != 0 {
		t.Fatalf("expected H1 packet-up POST not to close http.Client idle connections, got %d calls", got)
	}
}

func testPacketPayload() buf.MultiBuffer {
	return buf.MultiBuffer{buf.FromBytes([]byte("hello"))}
}

type writeOnlyConn struct{}

func (c *writeOnlyConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *writeOnlyConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *writeOnlyConn) Close() error                     { return nil }
func (c *writeOnlyConn) LocalAddr() stdnet.Addr           { return testAddr("local") }
func (c *writeOnlyConn) RemoteAddr() stdnet.Addr          { return testAddr("remote") }
func (c *writeOnlyConn) SetDeadline(time.Time) error      { return nil }
func (c *writeOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *writeOnlyConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }
