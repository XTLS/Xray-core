package masque

import (
	"bufio"
	"bytes"
	"context"
	go_errors "errors"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	http2MaxConcurrentStreams = 100
	http2HandshakeTimeout     = 10 * time.Second
	http2DefaultHeaderTable   = 4096
)

var (
	errHTTP2BadPreface        = go_errors.New("http2: invalid connection preface")
	errHTTP2BadRequest        = go_errors.New("http2: malformed request")
	errHTTP2StreamClosed      = go_errors.New("http2: stream closed")
	errHTTP2RequestBodyClosed = go_errors.New("http2: request body closed")
)

type connAddrsKey struct{}

type connAddrs struct {
	local  net.Addr
	remote net.Addr
}

type http2ServerConn struct {
	conn    net.Conn
	handler http.Handler
	ctx     context.Context
	cancel  context.CancelFunc

	wmu  sync.Mutex
	bw   *bufio.Writer
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder

	lastFrame atomic.Int64

	mu              sync.Mutex
	cond            sync.Cond
	err             error
	maxFrameSize    uint32
	initialWindow   int64
	connSendWindow  int64
	connRecvWindow  int64
	connRecvUnacked int64
	streams         map[uint32]*http2ServerStream
	lastStreamID    uint32
}

type http2ServerStream struct {
	c      *http2ServerConn
	id     uint32
	ctx    context.Context
	cancel context.CancelFunc
	header http.Header
	out    *connectip.StreamBuffer
	sent   chan struct{}

	sendWindow  int64
	recvWindow  int64
	recvUnacked int64
	recv        bytes.Buffer
	recvEnd     bool
	wroteHeader bool
	sentEnd     bool
	resetErr    error
}

func serveHTTP2(ctx context.Context, conn net.Conn, handler http.Handler) {
	ctx, cancel := context.WithCancel(ctx)
	c := &http2ServerConn{
		conn:           conn,
		handler:        handler,
		ctx:            context.WithValue(ctx, connAddrsKey{}, connAddrs{local: conn.LocalAddr(), remote: conn.RemoteAddr()}),
		cancel:         cancel,
		bw:             bufio.NewWriter(conn),
		maxFrameSize:   http2DefaultFrameSize,
		initialWindow:  http2DefaultWindow,
		connSendWindow: http2DefaultWindow,
		connRecvWindow: http2ConnectionWindow,
		streams:        make(map[uint32]*http2ServerStream),
	}
	c.cond.L = &c.mu
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.henc.SetMaxDynamicTableSizeLimit(0)
	c.lastFrame.Store(time.Now().UnixNano())

	br := bufio.NewReader(conn)
	preface := make([]byte, len(http2.ClientPreface))
	conn.SetReadDeadline(time.Now().Add(http2HandshakeTimeout))
	if _, err := io.ReadFull(br, preface); err != nil || string(preface) != http2.ClientPreface {
		c.fail(errHTTP2BadPreface)
		return
	}
	conn.SetReadDeadline(time.Time{})

	c.fr = http2.NewFramer(c.bw, br)
	c.fr.SetMaxReadFrameSize(http2DefaultFrameSize)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(http2DefaultHeaderTable, nil)
	c.fr.MaxHeaderListSize = http2MaxHeaderListSize
	if err := c.write(func(fr *http2.Framer) error {
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: http2MaxConcurrentStreams},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2StreamWindow},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: http2MaxHeaderListSize},
			http2.Setting{ID: http2.SettingEnableConnectProtocol, Val: 1},
		); err != nil {
			return err
		}
		return fr.WriteWindowUpdate(0, http2ConnectionWindow-http2DefaultWindow)
	}); err != nil {
		c.fail(err)
		return
	}
	go c.keepAlive()
	c.readLoop()
}

func (c *http2ServerConn) write(f func(*http2.Framer) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := f(c.fr); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *http2ServerConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	streams := slices.Collect(maps.Values(c.streams))
	c.cond.Broadcast()
	c.mu.Unlock()
	for _, st := range streams {
		st.out.CloseWithError(err)
		st.cancel()
	}
	c.cancel()
	c.conn.Close()
}

func (c *http2ServerConn) keepAlive() {
	ticker := time.NewTicker(http2KeepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		idle := time.Since(time.Unix(0, c.lastFrame.Load()))
		if idle >= http2IdleTimeout {
			c.fail(errHTTP2IdleTimeout)
			return
		}
		if idle >= http2KeepAlivePeriod {
			go c.write(func(fr *http2.Framer) error {
				return fr.WritePing(false, [8]byte{})
			})
		}
	}
}

func (c *http2ServerConn) readLoop() {
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var streamErr http2.StreamError
			if go_errors.As(err, &streamErr) {
				if err := c.resetStream(streamErr); err != nil {
					c.fail(err)
					return
				}
				continue
			}
			c.fail(err)
			return
		}
		c.lastFrame.Store(time.Now().UnixNano())
		if err := c.handleFrame(f); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *http2ServerConn) handleFrame(f http2.Frame) error {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			return nil
		}
		if err := c.applySettings(f); err != nil {
			return err
		}
		return c.write((*http2.Framer).WriteSettingsAck)
	case *http2.PingFrame:
		if f.IsAck() {
			return nil
		}
		return c.write(func(fr *http2.Framer) error {
			return fr.WritePing(true, f.Data)
		})
	case *http2.WindowUpdateFrame:
		return c.handleWindowUpdate(f)
	case *http2.MetaHeadersFrame:
		return c.handleHeaders(f)
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.RSTStreamFrame:
		c.abortStream(f.StreamID, http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode}, false)
	case *http2.PushPromiseFrame:
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	return nil
}

func (c *http2ServerConn) applySettings(f *http2.SettingsFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer c.cond.Broadcast()
	return f.ForeachSetting(func(s http2.Setting) error {
		if err := s.Valid(); err != nil {
			return err
		}
		switch s.ID {
		case http2.SettingMaxFrameSize:
			c.maxFrameSize = s.Val
		case http2.SettingInitialWindowSize:
			delta := int64(s.Val) - c.initialWindow
			c.initialWindow = int64(s.Val)
			for _, st := range c.streams {
				st.sendWindow += delta
				if st.sendWindow > math.MaxInt32 {
					return http2.ConnectionError(http2.ErrCodeFlowControl)
				}
			}
		}
		return nil
	})
}

func (c *http2ServerConn) handleWindowUpdate(f *http2.WindowUpdateFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.StreamID == 0 {
		c.connSendWindow += int64(f.Increment)
		if c.connSendWindow > math.MaxInt32 {
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
	} else if st := c.streams[f.StreamID]; st != nil {
		st.sendWindow += int64(f.Increment)
		if st.sendWindow > math.MaxInt32 {
			return http2.ConnectionError(http2.ErrCodeFlowControl)
		}
	}
	c.cond.Broadcast()
	return nil
}

func (c *http2ServerConn) handleHeaders(f *http2.MetaHeadersFrame) error {
	c.mu.Lock()
	if st := c.streams[f.StreamID]; st != nil {
		if !f.StreamEnded() {
			c.mu.Unlock()
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		st.recvEnd = true
		c.cond.Broadcast()
		c.mu.Unlock()
		return nil
	}
	if f.StreamID%2 == 0 || f.StreamID <= c.lastStreamID {
		c.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	c.lastStreamID = f.StreamID
	refused := len(c.streams) >= http2MaxConcurrentStreams
	c.mu.Unlock()

	if refused {
		return c.write(func(fr *http2.Framer) error {
			return fr.WriteRSTStream(f.StreamID, http2.ErrCodeRefusedStream)
		})
	}
	req, err := newHTTP2Request(f)
	if err != nil {
		return c.write(func(fr *http2.Framer) error {
			return fr.WriteRSTStream(f.StreamID, http2.ErrCodeProtocol)
		})
	}

	ctx, cancel := context.WithCancel(c.ctx)
	st := &http2ServerStream{
		c:          c,
		id:         f.StreamID,
		ctx:        ctx,
		cancel:     cancel,
		header:     make(http.Header),
		out:        connectip.NewStreamBuffer(),
		sent:       make(chan struct{}),
		recvWindow: http2StreamWindow,
		recvEnd:    f.StreamEnded(),
	}
	req = req.WithContext(ctx)
	req.RemoteAddr = c.conn.RemoteAddr().String()
	if st.recvEnd {
		req.Body = http.NoBody
		req.ContentLength = 0
	} else {
		req.Body = &http2RequestBody{st: st}
		req.ContentLength = -1
	}

	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		cancel()
		return err
	}
	st.sendWindow = c.initialWindow
	c.streams[f.StreamID] = st
	c.mu.Unlock()

	go c.serveStream(st, req)
	return nil
}

func newHTTP2Request(f *http2.MetaHeadersFrame) (*http.Request, error) {
	method := f.PseudoValue("method")
	scheme := f.PseudoValue("scheme")
	authority := f.PseudoValue("authority")
	path := f.PseudoValue("path")
	protocol := f.PseudoValue("protocol")
	if method == "" || (protocol != "" && method != http.MethodConnect) {
		return nil, errHTTP2BadRequest
	}
	var u *url.URL
	if method == http.MethodConnect && protocol == "" {
		if authority == "" || path != "" || scheme != "" {
			return nil, errHTTP2BadRequest
		}
		u = &url.URL{Host: authority}
	} else {
		if path == "" || scheme == "" {
			return nil, errHTTP2BadRequest
		}
		var err error
		if u, err = url.ParseRequestURI(path); err != nil {
			return nil, errHTTP2BadRequest
		}
	}
	header := make(http.Header)
	for _, hf := range f.RegularFields() {
		header.Add(hf.Name, hf.Value)
	}
	if protocol != "" {
		header.Set(":protocol", protocol)
	}
	if authority == "" {
		authority = header.Get("Host")
	}
	return &http.Request{
		Method:     method,
		URL:        u,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		Header:     header,
		Host:       authority,
		RequestURI: path,
	}, nil
}

func (c *http2ServerConn) handleData(f *http2.DataFrame) error {
	size := int64(f.Length)
	c.mu.Lock()
	c.connRecvWindow -= size
	if c.connRecvWindow < 0 {
		c.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	st := c.streams[f.StreamID]
	if st == nil || st.resetErr != nil || st.recvEnd {
		idle := st == nil && f.StreamID > c.lastStreamID
		c.connRecvWindow += size
		c.mu.Unlock()
		if idle {
			return http2.ConnectionError(http2.ErrCodeProtocol)
		}
		if size == 0 {
			return nil
		}
		return c.write(func(fr *http2.Framer) error {
			return fr.WriteWindowUpdate(0, uint32(size))
		})
	}
	st.recvWindow -= size
	if st.recvWindow < 0 {
		c.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	st.recv.Write(f.Data())
	padding := size - int64(len(f.Data()))
	st.recvUnacked += padding
	c.connRecvUnacked += padding
	if f.StreamEnded() {
		st.recvEnd = true
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

func (c *http2ServerConn) resetStream(streamErr http2.StreamError) error {
	c.mu.Lock()
	if streamErr.StreamID%2 == 1 && streamErr.StreamID > c.lastStreamID {
		c.lastStreamID = streamErr.StreamID
	}
	c.mu.Unlock()
	c.abortStream(streamErr.StreamID, streamErr, false)
	return c.write(func(fr *http2.Framer) error {
		return fr.WriteRSTStream(streamErr.StreamID, streamErr.Code)
	})
}

func (c *http2ServerConn) abortStream(id uint32, err error, reset bool) {
	c.mu.Lock()
	st := c.streams[id]
	if st == nil || st.resetErr != nil {
		c.mu.Unlock()
		return
	}
	st.resetErr = err
	c.cond.Broadcast()
	c.mu.Unlock()
	st.out.CloseWithError(err)
	st.cancel()
	if reset {
		go c.write(func(fr *http2.Framer) error {
			return fr.WriteRSTStream(id, http2.ErrCodeCancel)
		})
	}
}

func (c *http2ServerConn) serveStream(st *http2ServerStream, req *http.Request) {
	go st.sendLoop()
	c.handler.ServeHTTP(&http2ResponseWriter{st: st}, req)
	st.writeHeader(http.StatusOK)
	st.out.Close()
	<-st.sent

	c.mu.Lock()
	finish := st.resetErr == nil && !st.sentEnd && c.err == nil
	refuse := finish && !st.recvEnd
	st.sentEnd = true
	delete(c.streams, st.id)
	c.cond.Broadcast()
	c.mu.Unlock()
	st.cancel()

	if finish {
		if err := c.write(func(fr *http2.Framer) error {
			if err := fr.WriteData(st.id, true, nil); err != nil {
				return err
			}
			if refuse {
				return fr.WriteRSTStream(st.id, http2.ErrCodeNo)
			}
			return nil
		}); err != nil {
			c.fail(err)
		}
	}
}

func (st *http2ServerStream) writeHeader(code int) {
	c := st.c
	c.mu.Lock()
	if st.wroteHeader || st.resetErr != nil || c.err != nil {
		c.mu.Unlock()
		return
	}
	st.wroteHeader = true
	header := st.header.Clone()
	maxFrameSize := int(c.maxFrameSize)
	c.mu.Unlock()

	if err := c.write(func(fr *http2.Framer) error {
		c.hbuf.Reset()
		c.henc.WriteField(hpack.HeaderField{Name: ":status", Value: strconv.Itoa(code)})
		for _, k := range slices.Sorted(maps.Keys(header)) {
			name := strings.ToLower(k)
			switch name {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				continue
			}
			for _, v := range header[k] {
				c.henc.WriteField(hpack.HeaderField{Name: name, Value: v})
			}
		}
		block := c.hbuf.Bytes()
		for first := true; first || len(block) > 0; first = false {
			chunk := block[:min(len(block), maxFrameSize)]
			block = block[len(chunk):]
			var err error
			if first {
				err = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: st.id, BlockFragment: chunk, EndHeaders: len(block) == 0})
			} else {
				err = fr.WriteContinuation(st.id, len(block) == 0, chunk)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		c.fail(err)
	}
}

func (st *http2ServerStream) sendLoop() {
	defer close(st.sent)
	c := st.c
	buf := make([]byte, http2DefaultFrameSize)
	for {
		n, err := st.out.Read(buf)
		for data := buf[:n]; len(data) > 0; {
			allowed, err := st.awaitSendWindow(len(data))
			if err != nil {
				st.out.CloseWithError(err)
				return
			}
			if err := c.write(func(fr *http2.Framer) error {
				return fr.WriteData(st.id, false, data[:allowed])
			}); err != nil {
				c.fail(err)
				return
			}
			data = data[allowed:]
		}
		if err != nil {
			return
		}
	}
}

func (st *http2ServerStream) awaitSendWindow(n int) (int, error) {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		switch {
		case st.resetErr != nil:
			return 0, st.resetErr
		case c.err != nil:
			return 0, c.err
		case st.sentEnd:
			return 0, errHTTP2StreamClosed
		}
		if window := min(c.connSendWindow, st.sendWindow); window > 0 {
			n = int(min(int64(n), window, int64(c.maxFrameSize)))
			c.connSendWindow -= int64(n)
			st.sendWindow -= int64(n)
			return n, nil
		}
		c.cond.Wait()
	}
}

type http2ResponseWriter struct {
	st *http2ServerStream
}

func (w *http2ResponseWriter) Header() http.Header { return w.st.header }

func (w *http2ResponseWriter) WriteHeader(code int) { w.st.writeHeader(code) }

func (w *http2ResponseWriter) Write(p []byte) (int, error) {
	w.st.writeHeader(http.StatusOK)
	return w.st.out.Write(p)
}

func (w *http2ResponseWriter) Flush() { w.st.writeHeader(http.StatusOK) }

func (w *http2ResponseWriter) SetWriteDeadline(t time.Time) error {
	return w.st.out.SetWriteDeadline(t)
}

type http2RequestBody struct {
	st *http2ServerStream
}

func (b *http2RequestBody) Read(p []byte) (int, error) {
	st := b.st
	c := st.c
	c.mu.Lock()
	for st.recv.Len() == 0 && !st.recvEnd && st.resetErr == nil && c.err == nil {
		c.cond.Wait()
	}
	if st.recv.Len() == 0 {
		err := io.EOF
		switch {
		case st.resetErr != nil:
			err = st.resetErr
		case c.err != nil && !st.recvEnd:
			err = c.err
		}
		c.mu.Unlock()
		return 0, err
	}
	n, _ := st.recv.Read(p)
	st.recvUnacked += int64(n)
	c.connRecvUnacked += int64(n)
	var streamUpdate, connUpdate int64
	if st.recvUnacked >= http2WindowUpdateSize && !st.recvEnd {
		streamUpdate = st.recvUnacked
		st.recvUnacked = 0
		st.recvWindow += streamUpdate
	}
	if c.connRecvUnacked >= http2WindowUpdateSize {
		connUpdate = c.connRecvUnacked
		c.connRecvUnacked = 0
		c.connRecvWindow += connUpdate
	}
	c.mu.Unlock()

	if streamUpdate > 0 || connUpdate > 0 {
		if err := c.write(func(fr *http2.Framer) error {
			if connUpdate > 0 {
				if err := fr.WriteWindowUpdate(0, uint32(connUpdate)); err != nil {
					return err
				}
			}
			if streamUpdate > 0 {
				return fr.WriteWindowUpdate(st.id, uint32(streamUpdate))
			}
			return nil
		}); err != nil {
			c.fail(err)
		}
	}
	return n, nil
}

func (b *http2RequestBody) Close() error {
	st := b.st
	c := st.c
	c.mu.Lock()
	done := st.recvEnd
	c.mu.Unlock()
	if !done {
		c.abortStream(st.id, errHTTP2RequestBodyClosed, true)
	}
	return nil
}
