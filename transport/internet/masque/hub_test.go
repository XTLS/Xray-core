package masque

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestServerVersions(t *testing.T) {
	for _, c := range []struct {
		alpn   []string
		h2, h3 bool
	}{
		{alpn: nil, h3: true},
		{alpn: []string{"h3"}, h3: true},
		{alpn: []string{"h2"}, h2: true},
		{alpn: []string{"h2", "http/1.1"}, h2: true},
		{alpn: []string{"h3", "h2"}, h2: true, h3: true},
		{alpn: []string{"http/1.1"}, h3: true},
	} {
		h2, h3 := serverVersions(&tls.Config{NextProtocol: c.alpn})
		if h2 != c.h2 || h3 != c.h3 {
			t.Errorf("serverVersions(%q) = %v, %v, want %v, %v", c.alpn, h2, h3, c.h2, c.h3)
		}
	}
}

func TestPathMatcher(t *testing.T) {
	for _, c := range []struct {
		path    string
		request string
		want    bool
	}{
		{DefaultPath, "/.well-known/masque/ip/*/*/", true},
		{DefaultPath, "/.well-known/masque/ip/%2A/%2A/", true},
		{DefaultPath, "/.well-known/masque/ip/*/*", false},
		{DefaultPath, "/.well-known/masque/ip/*/*/?x=1", false},
		{DefaultPath, "/.well-known/masque/ip/192.0.2.1/6/", false},
		{"/masque?target=*&ipproto=*", "/masque?ipproto=*&target=*", true},
		{"/masque?target=*&ipproto=*", "/masque?target=*", false},
	} {
		m, err := newPathMatcher(c.path)
		require.NoError(t, err)
		u, err := url.ParseRequestURI(c.request)
		require.NoError(t, err)
		if got := m.match(u); got != c.want {
			t.Errorf("path %q matching %q = %v, want %v", c.path, c.request, got, c.want)
		}
	}
	_, err := newPathMatcher("masque")
	require.Error(t, err)
}

func connectIPRequest(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://proxy.example"+target, nil)
	r.Method = http.MethodConnect
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	r.Header.Set(":protocol", "connect-ip")
	r.Header.Set("Capsule-Protocol", "?1")
	r.Body = io.NopCloser(&blockingReader{})
	return r
}

type blockingReader struct{}

func (*blockingReader) Read([]byte) (int, error) {
	time.Sleep(time.Hour)
	return 0, io.EOF
}

func serve(t *testing.T, r *http.Request, handle func(*ServerConn)) *httptest.ResponseRecorder {
	t.Helper()
	path, err := newPathMatcher(DefaultPath)
	require.NoError(t, err)
	l := &Listener{path: path, addConn: func(conn stat.Connection) {
		go func() {
			handle(conn.(*ServerConn))
			conn.Close()
		}()
	}}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	defer l.cancel()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		l.ServeHTTP(w, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP did not return")
	}
	return w
}

func TestListenerRejectsOtherRequests(t *testing.T) {
	unexpected := func(*ServerConn) { t.Error("an invalid request reached the proxy") }

	require.Equal(t, http.StatusNotFound, serve(t, connectIPRequest("/other"), unexpected).Code)

	get := connectIPRequest(DefaultPath)
	get.Method = http.MethodGet
	require.Equal(t, http.StatusMethodNotAllowed, serve(t, get, unexpected).Code)

	websocket := connectIPRequest(DefaultPath)
	websocket.Header.Set(":protocol", "websocket")
	require.Equal(t, http.StatusNotImplemented, serve(t, websocket, unexpected).Code)

	noCapsules := connectIPRequest(DefaultPath)
	noCapsules.Header.Del("Capsule-Protocol")
	require.Equal(t, http.StatusBadRequest, serve(t, noCapsules, unexpected).Code)
}

func TestServerConnAnswers(t *testing.T) {
	t.Run("reject", func(t *testing.T) {
		w := serve(t, connectIPRequest(DefaultPath), func(conn *ServerConn) {
			require.Equal(t, "connect-ip", conn.Request().Header.Get(":protocol"))
			conn.Reject(http.StatusUnauthorized, http.Header{"WWW-Authenticate": {"Basic"}})
		})
		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Equal(t, "Basic", w.Header().Get("WWW-Authenticate"))
	})

	t.Run("no answer", func(t *testing.T) {
		w := serve(t, connectIPRequest(DefaultPath), func(*ServerConn) {})
		require.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("accept", func(t *testing.T) {
		w := serve(t, connectIPRequest(DefaultPath), func(conn *ServerConn) {
			ipConn, err := conn.Accept()
			require.NoError(t, err)
			require.NotNil(t, ipConn)
			_, err = conn.Accept()
			require.Error(t, err)
			conn.Reject(http.StatusForbidden, nil)
		})
		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "?1", w.Header().Get("Capsule-Protocol"))
	})
}
