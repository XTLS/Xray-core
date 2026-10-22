package websocket_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	xws "github.com/xtls/xray-core/transport/internet/websocket"
)

// newCloseServer starts a WebSocket server that sends one binary message and
// then a close frame carrying closePayload. The TCP connection stays open for a
// moment after the close frame so the client reads the close frame itself
// instead of an abnormal EOF.
func newCloseServer(t *testing.T, closePayload []byte) string {
	t.Helper()

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, []byte("response")); err != nil {
			return
		}
		if err := conn.WriteControl(websocket.CloseMessage, closePayload, time.Now().Add(time.Second)); err != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
		_ = conn.Close()
	}))
	t.Cleanup(server.Close)

	return server.Listener.Addr().String()
}

// dialForRead dials addr and wraps the WebSocket connection the same way the
// transport does.
func dialForRead(t *testing.T, addr string) io.ReadCloser {
	t.Helper()

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	conn, _, err := dialer.Dial("ws://"+addr+"/", nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Bound the reads so a lost close frame fails the test instead of hanging.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	wrapped := xws.NewConnection(conn, conn.RemoteAddr(), nil, 0)
	t.Cleanup(func() { _ = wrapped.Close() })

	return wrapped
}

// A close frame with a normal status ends the byte stream: a reader must see
// io.EOF after the last payload bytes, not a close error. An error there makes
// the outbound interrupt the pipe and drop the tail of the response.
func TestConnectionReadNormalCloseIsEOF(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{name: "normal closure 1000", payload: websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")},
		{name: "no status 1005", payload: []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialForRead(t, newCloseServer(t, tc.payload))
			buf := make([]byte, 64)

			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("first read: %v", err)
			}
			if string(buf[:n]) != "response" {
				t.Fatalf("first read payload = %q, want %q", buf[:n], "response")
			}

			n, err = conn.Read(buf)
			if n != 0 {
				t.Errorf("second read returned %d bytes, want 0", n)
			}
			if !errors.Is(err, io.EOF) {
				t.Fatalf("second read error = %v, want io.EOF", err)
			}
		})
	}
}

// Other close codes keep their error semantics.
func TestConnectionReadOtherCloseIsError(t *testing.T) {
	conn := dialForRead(t, newCloseServer(t, websocket.FormatCloseMessage(websocket.CloseGoingAway, "going away")))
	buf := make([]byte, 64)

	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("first read: %v", err)
	}

	n, err := conn.Read(buf)
	if n != 0 {
		t.Errorf("second read returned %d bytes, want 0", n)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("second read error = io.EOF, want a close error")
	}
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != websocket.CloseGoingAway {
		t.Fatalf("second read error = %v, want CloseError %d", err, websocket.CloseGoingAway)
	}
}
