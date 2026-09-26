package masque

import (
	"bufio"
	"bytes"
	"context"
	go_errors "errors"
	"io"
	"maps"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	http2StreamID          = 1
	http2DefaultWindow     = 65535
	http2DefaultFrameSize  = 16 << 10
	http2HeaderTableSize   = 64 << 10
	http2StreamWindow      = 6 << 20
	http2ConnectionWindow  = 15 << 20
	http2MaxHeaderListSize = 256 << 10
	http2WindowUpdateSize  = 1 << 20
	http2KeepAlivePeriod   = 10 * time.Second
	http2IdleTimeout       = 30 * time.Second
	http2DefaultUserAgent  = "Go-http-client/2.0"
)

var (
	errHTTP2StreamUsed        = go_errors.New("http2: the connection carries a single stream")
	errHTTP2NoExtendedConnect = go_errors.New("http2: the server did not enable extended CONNECT")
	errHTTP2BodyClosed        = go_errors.New("http2: response body closed")
	errHTTP2IdleTimeout       = go_errors.New("http2: no frame received within the idle timeout")
)

type http2ClientConn struct {
	conn net.Conn

	wmu  sync.Mutex
	bw   *bufio.Writer
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder

	lastFrame atomic.Int64
	settings  chan struct{}
	responses chan *http.Response
	aborted   chan struct{}
	done      chan struct{}

	mu               sync.Mutex
	cond             sync.Cond
	err              error
	gotSettings      bool
	extendedConnect  bool
	maxFrameSize     uint32
	initialWindow    int64
	connSendWindow   int64
	streamSendWindow int64
	connRecvWindow   int64
	streamRecvWindow int64
	streamOpen       bool
	gotResponse      bool
	sentEnd          bool
	recvEnd          bool
	streamErr        error
	reqBody          io.Closer
	recv             bytes.Buffer
	recvErr          error
	recvUnacked      int64
}

func newHTTP2ClientConn(conn net.Conn) (*http2ClientConn, error) {
	c := &http2ClientConn{
		conn:             conn,
		bw:               bufio.NewWriter(conn),
		settings:         make(chan struct{}),
		responses:        make(chan *http.Response, 1),
		aborted:          make(chan struct{}),
		done:             make(chan struct{}),
		maxFrameSize:     http2DefaultFrameSize,
		initialWindow:    http2DefaultWindow,
		connSendWindow:   http2DefaultWindow,
		connRecvWindow:   http2ConnectionWindow,
		streamRecvWindow: http2StreamWindow,
	}
	c.cond.L = &c.mu
	c.fr = http2.NewFramer(c.bw, bufio.NewReader(conn))
	c.fr.SetMaxReadFrameSize(http2DefaultFrameSize)
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.henc.SetMaxDynamicTableSizeLimit(0)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(http2HeaderTableSize, nil)
	c.fr.MaxHeaderListSize = http2MaxHeaderListSize
	c.lastFrame.Store(time.Now().UnixNano())

	if err := c.write(func(fr *http2.Framer) error {
		if _, err := c.bw.WriteString(http2.ClientPreface); err != nil {
			return err
		}
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingHeaderTableSize, Val: http2HeaderTableSize},
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: http2StreamWindow},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: http2MaxHeaderListSize},
		); err != nil {
			return err
		}
		return fr.WriteWindowUpdate(0, http2ConnectionWindow-http2DefaultWindow)
	}); err != nil {
		return nil, err
	}
	go c.readLoop()
	go c.keepAlive()
	return c, nil
}

func (c *http2ClientConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *http2ClientConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *http2ClientConn) Close() error {
	c.fail(net.ErrClosed)
	return nil
}

func (c *http2ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	rsp, err := c.roundTrip(req)
	if err != nil && req.Body != nil {
		req.Body.Close()
	}
	return rsp, err
}

func (c *http2ClientConn) roundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	select {
	case <-c.settings:
	case <-c.done:
		return nil, c.connErr()
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}

	c.mu.Lock()
	switch {
	case c.err != nil:
		err := c.err
		c.mu.Unlock()
		return nil, err
	case c.streamOpen:
		c.mu.Unlock()
		return nil, errHTTP2StreamUsed
	case req.Header.Get(":protocol") != "" && !c.extendedConnect:
		c.mu.Unlock()
		return nil, errHTTP2NoExtendedConnect
	}
	c.streamOpen = true
	c.streamSendWindow = c.initialWindow
	c.reqBody = req.Body
	maxFrameSize := int(c.maxFrameSize)
	c.mu.Unlock()

	if err := c.writeHeaders(req, maxFrameSize); err != nil {
		c.fail(err)
		return nil, err
	}
	if req.Body != nil {
		go c.writeBody(req.Body)
	} else {
		c.endStream()
	}
	context.AfterFunc(ctx, func() { c.abortStream(context.Cause(ctx), true) })

	select {
	case rsp := <-c.responses:
		return rsp, nil
	case <-c.aborted:
		c.mu.Lock()
		err := c.streamErr
		c.mu.Unlock()
		return nil, err
	}
}

func (c *http2ClientConn) writeHeaders(req *http.Request, maxFrameSize int) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	c.hbuf.Reset()
	field := func(name, value string) {
		c.henc.WriteField(hpack.HeaderField{Name: name, Value: value})
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	field(":method", req.Method)
	field(":authority", host)
	field(":scheme", req.URL.Scheme)
	field(":path", req.URL.RequestURI())
	if protocol := req.Header.Get(":protocol"); protocol != "" {
		field(":protocol", protocol)
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		field("user-agent", http2DefaultUserAgent)
	}
	for _, k := range slices.Sorted(maps.Keys(req.Header)) {
		name := strings.ToLower(k)
		switch name {
		case ":protocol", "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade", "content-length":
			continue
		}
		for _, v := range req.Header[k] {
			if name == "user-agent" && v == "" {
				continue
			}
			field(name, v)
		}
	}

	block := c.hbuf.Bytes()
	for first := true; first || len(block) > 0; first = false {
		chunk := block[:min(len(block), maxFrameSize)]
		block = block[len(chunk):]
		var err error
		if first {
			err = c.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: http2StreamID, BlockFragment: chunk, EndHeaders: len(block) == 0})
		} else {
			err = c.fr.WriteContinuation(http2StreamID, len(block) == 0, chunk)
		}
		if err != nil {
			return err
		}
	}
	return c.bw.Flush()
}

func (c *http2ClientConn) writeBody(body io.ReadCloser) {
	defer body.Close()
	buf := make([]byte, http2DefaultFrameSize)
	for {
		n, err := body.Read(buf)
		for data := buf[:n]; len(data) > 0; {
			allowed, err := c.awaitSendWindow(len(data))
			if err != nil {
				return
			}
			if err := c.write(func(fr *http2.Framer) error {
				return fr.WriteData(http2StreamID, false, data[:allowed])
			}); err != nil {
				c.fail(err)
				return
			}
			data = data[allowed:]
		}
		if err == io.EOF {
			c.endStream()
			return
		}
		if err != nil {
			c.abortStream(err, true)
			return
		}
	}
}

func (c *http2ClientConn) awaitSendWindow(n int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.streamErr != nil {
			return 0, c.streamErr
		}
		if window := min(c.connSendWindow, c.streamSendWindow); window > 0 {
			n = int(min(int64(n), window, int64(c.maxFrameSize)))
			c.connSendWindow -= int64(n)
			c.streamSendWindow -= int64(n)
			return n, nil
		}
		c.cond.Wait()
	}
}

func (c *http2ClientConn) endStream() {
	c.mu.Lock()
	if c.streamErr != nil || c.sentEnd {
		c.mu.Unlock()
		return
	}
	c.sentEnd = true
	c.mu.Unlock()
	if err := c.write(func(fr *http2.Framer) error {
		return fr.WriteData(http2StreamID, true, nil)
	}); err != nil {
		c.fail(err)
	}
}

func (c *http2ClientConn) write(f func(*http2.Framer) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := f(c.fr); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *http2ClientConn) connErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *http2ClientConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.mu.Unlock()
	c.abortStream(err, false)
	c.conn.Close()
}

func (c *http2ClientConn) abortStream(err error, reset bool) {
	c.mu.Lock()
	if c.streamErr != nil {
		c.mu.Unlock()
		return
	}
	c.streamErr = err
	if c.recvErr == nil {
		c.recvErr = err
	}
	reset = reset && c.streamOpen && !(c.sentEnd && c.recvEnd)
	body := c.reqBody
	close(c.aborted)
	c.cond.Broadcast()
	c.mu.Unlock()

	if body != nil {
		body.Close()
	}
	if reset {
		go c.write(func(fr *http2.Framer) error {
			return fr.WriteRSTStream(http2StreamID, http2.ErrCodeCancel)
		})
	}
}

func (c *http2ClientConn) keepAlive() {
	ticker := time.NewTicker(http2KeepAlivePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
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

func (c *http2ClientConn) readLoop() {
	defer close(c.done)
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var streamErr http2.StreamError
			if go_errors.As(err, &streamErr) && streamErr.StreamID == http2StreamID {
				c.abortStream(streamErr, true)
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

func (c *http2ClientConn) handleFrame(f http2.Frame) error {
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
		c.mu.Lock()
		switch f.StreamID {
		case 0:
			c.connSendWindow += int64(f.Increment)
		case http2StreamID:
			c.streamSendWindow += int64(f.Increment)
		}
		c.cond.Broadcast()
		c.mu.Unlock()
	case *http2.MetaHeadersFrame:
		if f.StreamID == http2StreamID {
			c.handleHeaders(f)
		}
	case *http2.DataFrame:
		return c.handleData(f)
	case *http2.RSTStreamFrame:
		if f.StreamID == http2StreamID {
			c.abortStream(http2.StreamError{StreamID: f.StreamID, Code: f.ErrCode}, false)
		}
	case *http2.GoAwayFrame:
		if f.ErrCode != http2.ErrCodeNo || f.LastStreamID < http2StreamID {
			return errors.New("http2: the server sent GOAWAY (", f.ErrCode, ")")
		}
	case *http2.PushPromiseFrame:
		return http2.ConnectionError(http2.ErrCodeProtocol)
	}
	return nil
}

func (c *http2ClientConn) applySettings(f *http2.SettingsFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := f.ForeachSetting(func(s http2.Setting) error {
		if err := s.Valid(); err != nil {
			return err
		}
		switch s.ID {
		case http2.SettingMaxFrameSize:
			c.maxFrameSize = s.Val
		case http2.SettingInitialWindowSize:
			c.streamSendWindow += int64(s.Val) - c.initialWindow
			c.initialWindow = int64(s.Val)
		case http2.SettingEnableConnectProtocol:
			if !c.gotSettings {
				c.extendedConnect = s.Val == 1
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if !c.gotSettings {
		c.gotSettings = true
		close(c.settings)
	}
	c.cond.Broadcast()
	return nil
}

func (c *http2ClientConn) handleHeaders(f *http2.MetaHeadersFrame) {
	c.mu.Lock()
	gotResponse := c.gotResponse
	c.mu.Unlock()
	if !gotResponse {
		status, err := strconv.Atoi(f.PseudoValue("status"))
		if err != nil || status < 100 || status > 999 {
			c.abortStream(errors.New("http2: invalid response status ", strconv.Quote(f.PseudoValue("status"))), true)
			return
		}
		if status < 200 {
			return
		}
		header := make(http.Header)
		for _, hf := range f.RegularFields() {
			header.Add(hf.Name, hf.Value)
		}
		c.mu.Lock()
		c.gotResponse = true
		c.mu.Unlock()
		c.responses <- &http.Response{
			Status:        strconv.Itoa(status) + " " + http.StatusText(status),
			StatusCode:    status,
			Proto:         "HTTP/2.0",
			ProtoMajor:    2,
			Header:        header,
			Body:          &http2ResponseBody{c},
			ContentLength: -1,
		}
	}
	if f.StreamEnded() {
		c.mu.Lock()
		c.recvEnd = true
		if c.recvErr == nil {
			c.recvErr = io.EOF
		}
		c.cond.Broadcast()
		c.mu.Unlock()
	}
}

func (c *http2ClientConn) handleData(f *http2.DataFrame) error {
	size := int64(f.Length)
	c.mu.Lock()
	c.connRecvWindow -= size
	if c.connRecvWindow < 0 {
		c.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	if f.StreamID != http2StreamID || c.recvErr != nil {
		c.connRecvWindow += size
		c.mu.Unlock()
		if size == 0 {
			return nil
		}
		return c.write(func(fr *http2.Framer) error {
			return fr.WriteWindowUpdate(0, uint32(size))
		})
	}
	c.streamRecvWindow -= size
	if c.streamRecvWindow < 0 {
		c.mu.Unlock()
		return http2.ConnectionError(http2.ErrCodeFlowControl)
	}
	c.recv.Write(f.Data())
	c.recvUnacked += size - int64(len(f.Data()))
	if f.StreamEnded() {
		c.recvEnd = true
		c.recvErr = io.EOF
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	return nil
}

type http2ResponseBody struct {
	c *http2ClientConn
}

func (b *http2ResponseBody) Read(p []byte) (int, error) {
	c := b.c
	c.mu.Lock()
	for c.recv.Len() == 0 && c.recvErr == nil {
		c.cond.Wait()
	}
	if c.recv.Len() == 0 {
		err := c.recvErr
		c.mu.Unlock()
		return 0, err
	}
	n, _ := c.recv.Read(p)
	c.recvUnacked += int64(n)
	var update int64
	if c.recvUnacked >= http2WindowUpdateSize && !c.recvEnd {
		update = c.recvUnacked
		c.recvUnacked = 0
		c.connRecvWindow += update
		c.streamRecvWindow += update
	}
	c.mu.Unlock()

	if update > 0 {
		if err := c.write(func(fr *http2.Framer) error {
			if err := fr.WriteWindowUpdate(0, uint32(update)); err != nil {
				return err
			}
			return fr.WriteWindowUpdate(http2StreamID, uint32(update))
		}); err != nil {
			c.fail(err)
		}
	}
	return n, nil
}

func (b *http2ResponseBody) Close() error {
	b.c.abortStream(errHTTP2BodyClosed, true)
	return nil
}
