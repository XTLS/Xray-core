package masque

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func serveHTTP2Pipe(t *testing.T, handler http.Handler) net.Conn {
	t.Helper()
	client, server := tcpPipe(t)
	done := make(chan struct{})
	go func() {
		serveHTTP2(context.Background(), server, handler)
		close(done)
	}()
	t.Cleanup(func() {
		client.Close()
		server.Close()
		<-done
	})
	return client
}

type http2ClientPeer struct {
	t    *testing.T
	conn net.Conn
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder
}

func newHTTP2ClientPeer(t *testing.T, handler http.Handler) (*http2ClientPeer, []http2.Setting) {
	t.Helper()
	conn := serveHTTP2Pipe(t, handler)
	p := &http2ClientPeer{t: t, conn: conn, fr: http2.NewFramer(conn, conn)}
	p.henc = hpack.NewEncoder(&p.hbuf)
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	_, err := io.WriteString(conn, http2.ClientPreface)
	require.NoError(t, err)
	require.NoError(t, p.fr.WriteSettings())

	f := p.readFrame()
	require.IsType(t, &http2.SettingsFrame{}, f)
	var settings []http2.Setting
	f.(*http2.SettingsFrame).ForeachSetting(func(s http2.Setting) error {
		settings = append(settings, s)
		return nil
	})
	f = p.readFrame()
	require.IsType(t, &http2.WindowUpdateFrame{}, f)
	require.Equal(t, uint32(http2ConnectionWindow-http2DefaultWindow), f.(*http2.WindowUpdateFrame).Increment)
	f = p.readFrame()
	require.True(t, f.(*http2.SettingsFrame).IsAck())
	require.NoError(t, p.fr.WriteSettingsAck())
	return p, settings
}

func (p *http2ClientPeer) readFrame() http2.Frame {
	p.t.Helper()
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := p.fr.ReadFrame()
	require.NoError(p.t, err)
	return f
}

func (p *http2ClientPeer) writeHeaders(streamID uint32, endStream bool, fields ...string) {
	p.t.Helper()
	p.hbuf.Reset()
	for i := 0; i < len(fields); i += 2 {
		require.NoError(p.t, p.henc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: p.hbuf.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}))
}

func (p *http2ClientPeer) writeConnect(streamID uint32) {
	p.t.Helper()
	p.writeHeaders(streamID, false,
		":method", "CONNECT",
		":protocol", "connect-ip",
		":scheme", "https",
		":authority", "proxy.example",
		":path", "/.well-known/masque/ip/*/*/",
		"capsule-protocol", "?1",
	)
}

func TestHTTP2ServerSettings(t *testing.T) {
	_, settings := newHTTP2ClientPeer(t, http.NotFoundHandler())
	require.Equal(t, []http2.Setting{
		{ID: http2.SettingMaxConcurrentStreams, Val: http2MaxConcurrentStreams},
		{ID: http2.SettingInitialWindowSize, Val: http2StreamWindow},
		{ID: http2.SettingMaxHeaderListSize, Val: http2MaxHeaderListSize},
		{ID: http2.SettingEnableConnectProtocol, Val: 1},
	}, settings)
}

func TestHTTP2ServerRoundTrip(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodConnect, r.Method)
		assert.Equal(t, "connect-ip", r.Header.Get(":protocol"))
		assert.Equal(t, "?1", r.Header.Get("Capsule-Protocol"))
		assert.Equal(t, "Basic dTpw", r.Header.Get("Authorization"))
		assert.Equal(t, 2, r.ProtoMajor)
		assert.Equal(t, "proxy.example", r.Host)
		assert.Equal(t, "/.well-known/masque/ip/*/*/", r.URL.Path)
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		assert.NoError(t, http.NewResponseController(w).Flush())
		_, err := io.Copy(w, r.Body)
		assert.NoError(t, err)
	})
	cc, err := newHTTP2ClientConn(serveHTTP2Pipe(t, handler))
	require.NoError(t, err)
	defer cc.Close()

	pr, pw := io.Pipe()
	rsp, err := cc.RoundTrip(connectRequest(t, context.Background(), pr))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
	require.Equal(t, "?1", rsp.Header.Get("Capsule-Protocol"))

	payload := make([]byte, 3*http2ConnectionWindow/2)
	rand.Read(payload)
	go func() {
		pw.Write(payload)
		pw.Close()
	}()
	echoed := sha256.New()
	n, err := io.Copy(echoed, rsp.Body)
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), n)
	require.Equal(t, sha256.Sum256(payload), [32]byte(echoed.Sum(nil)))
}

func TestHTTP2ServerStatus(t *testing.T) {
	p, _ := newHTTP2ClientPeer(t, http.NotFoundHandler())
	p.writeConnect(1)
	f := p.readFrame()
	require.IsType(t, &http2.MetaHeadersFrame{}, f)
	require.Equal(t, "404", f.(*http2.MetaHeadersFrame).PseudoValue("status"))
	var body []byte
	for {
		f = p.readFrame()
		require.IsType(t, &http2.DataFrame{}, f)
		body = append(body, f.(*http2.DataFrame).Data()...)
		if f.(*http2.DataFrame).StreamEnded() {
			break
		}
	}
	require.Equal(t, "404 page not found\n", string(body))
	f = p.readFrame()
	require.IsType(t, &http2.RSTStreamFrame{}, f)
	require.Equal(t, http2.ErrCodeNo, f.(*http2.RSTStreamFrame).ErrCode)
}

func TestHTTP2ServerMalformedRequests(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields []string
	}{
		{"no method", []string{":scheme", "https", ":path", "/", ":authority", "proxy.example"}},
		{"no path", []string{":method", "GET", ":scheme", "https", ":authority", "proxy.example"}},
		{"protocol without CONNECT", []string{":method", "GET", ":protocol", "connect-ip", ":scheme", "https", ":path", "/", ":authority", "proxy.example"}},
		{"plain CONNECT with a path", []string{":method", "CONNECT", ":path", "/", ":authority", "proxy.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newHTTP2ClientPeer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("the handler saw a malformed request")
			}))
			p.writeHeaders(1, false, tc.fields...)
			f := p.readFrame()
			require.IsType(t, &http2.RSTStreamFrame{}, f)
			require.Equal(t, http2.ErrCodeProtocol, f.(*http2.RSTStreamFrame).ErrCode)
		})
	}
}

func TestHTTP2ServerRefusesExtraStreams(t *testing.T) {
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(http2MaxConcurrentStreams)
	p, _ := newHTTP2ClientPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Done()
		<-release
	}))
	defer close(release)
	for i := range http2MaxConcurrentStreams {
		p.writeConnect(uint32(2*i + 1))
	}
	started.Wait()
	p.writeConnect(2*http2MaxConcurrentStreams + 1)
	f := p.readFrame()
	require.IsType(t, &http2.RSTStreamFrame{}, f)
	require.Equal(t, uint32(2*http2MaxConcurrentStreams+1), f.Header().StreamID)
	require.Equal(t, http2.ErrCodeRefusedStream, f.(*http2.RSTStreamFrame).ErrCode)
}

func TestHTTP2ServerClientReset(t *testing.T) {
	readErr := make(chan error, 1)
	canceled := make(chan struct{})
	p, _ := newHTTP2ClientPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := r.Body.Read(make([]byte, 1))
		readErr <- err
		<-r.Context().Done()
		close(canceled)
	}))
	p.writeConnect(1)
	f := p.readFrame()
	require.Equal(t, "200", f.(*http2.MetaHeadersFrame).PseudoValue("status"))
	require.NoError(t, p.fr.WriteRSTStream(1, http2.ErrCodeCancel))
	select {
	case err := <-readErr:
		require.Equal(t, http2.StreamError{StreamID: 1, Code: http2.ErrCodeCancel}, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the body read did not fail after RST_STREAM")
	}
	select {
	case <-canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the request context was not canceled")
	}
}

func TestHTTP2ServerAnswersPings(t *testing.T) {
	p, _ := newHTTP2ClientPeer(t, http.NotFoundHandler())
	data := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	require.NoError(t, p.fr.WritePing(false, data))
	f := p.readFrame()
	require.IsType(t, &http2.PingFrame{}, f)
	require.True(t, f.(*http2.PingFrame).IsAck())
	require.Equal(t, data, f.(*http2.PingFrame).Data)
}

func TestHTTP2ServerRejectsOverflow(t *testing.T) {
	p, _ := newHTTP2ClientPeer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		<-r.Context().Done()
	}))
	p.writeConnect(1)
	p.readFrame()
	chunk := make([]byte, http2DefaultFrameSize)
	go func() {
		for range http2StreamWindow/len(chunk) + 1 {
			if p.fr.WriteData(1, false, chunk) != nil {
				return
			}
		}
	}()
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.Copy(io.Discard, p.conn)
	require.NoError(t, err)
}

func TestHTTP2ServerBadPreface(t *testing.T) {
	conn := serveHTTP2Pipe(t, http.NotFoundHandler())
	_, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	require.NoError(t, err)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := io.Copy(io.Discard, conn)
	require.NoError(t, err)
	require.Zero(t, n)
}
