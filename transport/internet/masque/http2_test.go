package masque

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type http2Peer struct {
	t    *testing.T
	conn net.Conn
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder
}

func tcpPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		accepted <- conn
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	server := <-accepted
	require.NotNil(t, server)
	return client, server
}

func newHTTP2Peer(t *testing.T, settings ...http2.Setting) (*http2ClientConn, *http2Peer) {
	t.Helper()
	client, server := tcpPipe(t)
	p := &http2Peer{t: t, conn: server, fr: http2.NewFramer(server, server)}
	p.henc = hpack.NewEncoder(&p.hbuf)
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	t.Cleanup(func() { server.Close() })

	ccErr := make(chan error, 1)
	var cc *http2ClientConn
	go func() {
		var err error
		cc, err = newHTTP2ClientConn(client)
		ccErr <- err
	}()
	preface := make([]byte, len(http2.ClientPreface))
	_, err := io.ReadFull(server, preface)
	require.NoError(t, err)
	require.Equal(t, http2.ClientPreface, string(preface))

	f := p.readFrame()
	require.IsType(t, &http2.SettingsFrame{}, f)
	var got []http2.Setting
	f.(*http2.SettingsFrame).ForeachSetting(func(s http2.Setting) error {
		got = append(got, s)
		return nil
	})
	require.Equal(t, []http2.Setting{
		{ID: http2.SettingHeaderTableSize, Val: http2HeaderTableSize},
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: http2StreamWindow},
		{ID: http2.SettingMaxHeaderListSize, Val: http2MaxHeaderListSize},
	}, got)
	f = p.readFrame()
	require.IsType(t, &http2.WindowUpdateFrame{}, f)
	require.Equal(t, uint32(0), f.Header().StreamID)
	require.Equal(t, uint32(http2ConnectionWindow-http2DefaultWindow), f.(*http2.WindowUpdateFrame).Increment)
	require.NoError(t, <-ccErr)
	t.Cleanup(func() { cc.Close() })

	require.NoError(t, p.fr.WriteSettings(settings...))
	f = p.readFrame()
	require.IsType(t, &http2.SettingsFrame{}, f)
	require.True(t, f.(*http2.SettingsFrame).IsAck())
	return cc, p
}

func (p *http2Peer) readFrame() http2.Frame {
	p.t.Helper()
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	f, err := p.fr.ReadFrame()
	require.NoError(p.t, err)
	return f
}

func (p *http2Peer) writeHeaders(endStream bool, fields ...string) {
	p.t.Helper()
	p.hbuf.Reset()
	for i := 0; i < len(fields); i += 2 {
		require.NoError(p.t, p.henc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]}))
	}
	require.NoError(p.t, p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      http2StreamID,
		BlockFragment: p.hbuf.Bytes(),
		EndHeaders:    true,
		EndStream:     endStream,
	}))
}

func connectRequest(t *testing.T, ctx context.Context, body io.ReadCloser) *http.Request {
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://proxy.example/.well-known/masque/ip/*/*/", body)
	require.NoError(t, err)
	req.Header[":protocol"] = []string{"connect-ip"}
	req.Header.Set("Capsule-Protocol", "?1")
	req.Header.Set("Authorization", "Basic dTpw")
	req.Header["User-Agent"] = nil
	return req
}

func TestHTTP2ClientRequest(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	pr, pw := io.Pipe()

	type result struct {
		rsp *http.Response
		err error
	}
	results := make(chan result, 1)
	go func() {
		rsp, err := cc.RoundTrip(connectRequest(t, context.Background(), pr))
		results <- result{rsp, err}
	}()

	f := p.readFrame()
	require.IsType(t, &http2.MetaHeadersFrame{}, f)
	headers := f.(*http2.MetaHeadersFrame)
	require.False(t, headers.StreamEnded())
	var fields []string
	for _, hf := range headers.Fields {
		fields = append(fields, hf.Name+": "+hf.Value)
	}
	require.Equal(t, []string{
		":method: CONNECT",
		":authority: proxy.example",
		":scheme: https",
		":path: /.well-known/masque/ip/*/*/",
		":protocol: connect-ip",
		"authorization: Basic dTpw",
		"capsule-protocol: ?1",
	}, fields)

	p.writeHeaders(false, ":status", "200", "capsule-protocol", "?1")
	r := <-results
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.rsp.StatusCode)
	require.Equal(t, "?1", r.rsp.Header.Get("Capsule-Protocol"))

	go pw.Write([]byte("ping"))
	f = p.readFrame()
	require.IsType(t, &http2.DataFrame{}, f)
	require.Equal(t, "ping", string(f.(*http2.DataFrame).Data()))

	require.NoError(t, p.fr.WriteData(http2StreamID, false, []byte("pong")))
	b := make([]byte, 16)
	n, err := r.rsp.Body.Read(b)
	require.NoError(t, err)
	require.Equal(t, "pong", string(b[:n]))

	require.NoError(t, pw.Close())
	f = p.readFrame()
	require.IsType(t, &http2.DataFrame{}, f)
	require.True(t, f.(*http2.DataFrame).StreamEnded())

	require.NoError(t, p.fr.WriteData(http2StreamID, true, nil))
	_, err = r.rsp.Body.Read(b)
	require.ErrorIs(t, err, io.EOF)
}

func TestHTTP2ClientDefaultUserAgent(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	req := connectRequest(t, context.Background(), nil)
	delete(req.Header, "User-Agent")
	go cc.RoundTrip(req)
	f := p.readFrame()
	require.IsType(t, &http2.MetaHeadersFrame{}, f)
	var userAgents []string
	for _, hf := range f.(*http2.MetaHeadersFrame).Fields {
		if hf.Name == "user-agent" {
			userAgents = append(userAgents, hf.Value)
		}
	}
	require.Equal(t, []string{http2DefaultUserAgent}, userAgents)
}

func TestHTTP2ClientNeedsExtendedConnect(t *testing.T) {
	cc, _ := newHTTP2Peer(t)
	_, err := cc.RoundTrip(connectRequest(t, context.Background(), io.NopCloser(strings.NewReader(""))))
	require.ErrorIs(t, err, errHTTP2NoExtendedConnect)
}

func TestHTTP2ClientSingleStream(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	go cc.RoundTrip(connectRequest(t, context.Background(), nil))
	p.readFrame()
	_, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
	require.ErrorIs(t, err, errHTTP2StreamUsed)
}

func TestHTTP2ClientFlowControl(t *testing.T) {
	cc, p := newHTTP2Peer(t,
		http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 10},
	)
	pr, pw := io.Pipe()
	go cc.RoundTrip(connectRequest(t, context.Background(), pr))
	require.IsType(t, &http2.MetaHeadersFrame{}, p.readFrame())

	go pw.Write([]byte("0123456789abcdef"))
	f := p.readFrame()
	require.Equal(t, "0123456789", string(f.(*http2.DataFrame).Data()))

	require.NoError(t, p.fr.WriteWindowUpdate(http2StreamID, 4))
	f = p.readFrame()
	require.Equal(t, "abcd", string(f.(*http2.DataFrame).Data()))

	require.NoError(t, p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 12}))
	var acked bool
	var data string
	for range 2 {
		switch f := p.readFrame().(type) {
		case *http2.SettingsFrame:
			acked = f.IsAck()
		case *http2.DataFrame:
			data = string(f.Data())
		}
	}
	require.True(t, acked)
	require.Equal(t, "ef", data)
}

func TestHTTP2ClientReceiveWindow(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	rsps := make(chan *http.Response, 1)
	go func() {
		rsp, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
		if err == nil {
			rsps <- rsp
		}
	}()
	require.IsType(t, &http2.MetaHeadersFrame{}, p.readFrame())
	require.True(t, p.readFrame().(*http2.DataFrame).StreamEnded())
	p.writeHeaders(false, ":status", "200")
	rsp := <-rsps

	chunk := bytes.Repeat([]byte("x"), http2DefaultFrameSize)
	sent := 0
	go func() {
		for sent+len(chunk) <= http2WindowUpdateSize {
			if p.fr.WriteData(http2StreamID, false, chunk) != nil {
				return
			}
			sent += len(chunk)
		}
	}()
	_, err := io.CopyN(io.Discard, rsp.Body, http2WindowUpdateSize)
	require.NoError(t, err)
	for _, id := range []uint32{0, http2StreamID} {
		f := p.readFrame()
		require.IsType(t, &http2.WindowUpdateFrame{}, f)
		require.Equal(t, id, f.Header().StreamID)
		require.Equal(t, uint32(http2WindowUpdateSize), f.(*http2.WindowUpdateFrame).Increment)
	}
}

func TestHTTP2ClientRejectsOverflow(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	rsps := make(chan *http.Response, 1)
	go func() {
		rsp, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
		if err == nil {
			rsps <- rsp
		}
	}()
	p.readFrame()
	p.readFrame()
	p.writeHeaders(false, ":status", "200")
	rsp := <-rsps

	chunk := make([]byte, http2DefaultFrameSize)
	go func() {
		for range http2StreamWindow/len(chunk) + 1 {
			if p.fr.WriteData(http2StreamID, false, chunk) != nil {
				return
			}
		}
	}()
	select {
	case <-cc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection outlived a flow control violation")
	}
	require.ErrorIs(t, cc.connErr(), http2.ConnectionError(http2.ErrCodeFlowControl))
	_, err := io.Copy(io.Discard, rsp.Body)
	require.ErrorIs(t, err, http2.ConnectionError(http2.ErrCodeFlowControl))
}

func TestHTTP2ClientRejectsOversizedFrames(t *testing.T) {
	cc, p := newHTTP2Peer(t)
	require.NoError(t, p.fr.WritePing(false, [8]byte{}))
	require.True(t, p.readFrame().(*http2.PingFrame).IsAck())

	p.fr.AllowIllegalWrites = true
	require.NoError(t, p.fr.WriteData(http2StreamID, false, make([]byte, http2DefaultFrameSize+1)))
	select {
	case <-cc.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection accepted a frame larger than it allows")
	}
	require.ErrorIs(t, cc.connErr(), http2.ErrFrameTooLarge)
}

func TestHTTP2ClientStatus(t *testing.T) {
	cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
	rsps := make(chan *http.Response, 1)
	go func() {
		rsp, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
		if err == nil {
			rsps <- rsp
		}
	}()
	p.readFrame()
	p.readFrame()
	p.writeHeaders(false, ":status", "100")
	p.writeHeaders(true, ":status", "407", "proxy-authenticate", "Basic")
	rsp := <-rsps
	require.Equal(t, http.StatusProxyAuthRequired, rsp.StatusCode)
	require.Equal(t, "Basic", rsp.Header.Get("Proxy-Authenticate"))
	_, err := rsp.Body.Read(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)
}

func TestHTTP2ClientReset(t *testing.T) {
	t.Run("by the server", func(t *testing.T) {
		cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
		errs := make(chan error, 1)
		go func() {
			_, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
			errs <- err
		}()
		p.readFrame()
		p.readFrame()
		require.NoError(t, p.fr.WriteRSTStream(http2StreamID, http2.ErrCodeRefusedStream))
		require.Equal(t, http2.StreamError{StreamID: http2StreamID, Code: http2.ErrCodeRefusedStream}, <-errs)
	})

	t.Run("by the context", func(t *testing.T) {
		cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
		ctx, cancel := context.WithCancel(context.Background())
		pr, pw := io.Pipe()
		defer pw.Close()
		rsps := make(chan *http.Response, 1)
		go func() {
			rsp, err := cc.RoundTrip(connectRequest(t, ctx, pr))
			if err == nil {
				rsps <- rsp
			}
		}()
		p.readFrame()
		p.writeHeaders(false, ":status", "200")
		rsp := <-rsps
		cancel()
		f := p.readFrame()
		require.IsType(t, &http2.RSTStreamFrame{}, f)
		require.Equal(t, http2.ErrCodeCancel, f.(*http2.RSTStreamFrame).ErrCode)
		_, err := rsp.Body.Read(make([]byte, 1))
		require.ErrorIs(t, err, context.Canceled)
		_, err = pw.Write([]byte("x"))
		require.ErrorIs(t, err, io.ErrClosedPipe)
	})

	t.Run("by GOAWAY", func(t *testing.T) {
		cc, p := newHTTP2Peer(t, http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1})
		errs := make(chan error, 1)
		go func() {
			_, err := cc.RoundTrip(connectRequest(t, context.Background(), nil))
			errs <- err
		}()
		p.readFrame()
		p.readFrame()
		require.NoError(t, p.fr.WriteGoAway(0, http2.ErrCodeNo, nil))
		require.ErrorContains(t, <-errs, "GOAWAY")
	})
}

func TestHTTP2ClientAnswersPings(t *testing.T) {
	_, p := newHTTP2Peer(t)
	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	require.NoError(t, p.fr.WritePing(false, data))
	f := p.readFrame()
	require.IsType(t, &http2.PingFrame{}, f)
	require.True(t, f.(*http2.PingFrame).IsAck())
	require.Equal(t, data, f.(*http2.PingFrame).Data)
}
