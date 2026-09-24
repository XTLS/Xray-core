package connectip

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/apernet/quic-go"
)

const maxBufferedRequestBody = 32 << 10

type HTTP2ClientConn struct {
	roundTripper http.RoundTripper
}

func NewHTTP2ClientConn(rt http.RoundTripper) *HTTP2ClientConn {
	return &HTTP2ClientConn{roundTripper: rt}
}

func (c *HTTP2ClientConn) Dial(req *Request) (*Conn, *http.Response, error) {
	httpReq := req.httpRequest()
	if httpReq.URL == nil {
		return nil, nil, errors.New("connect-ip: request URL is nil")
	}
	if httpReq.Host == "" && httpReq.URL.Host == "" {
		return nil, nil, errors.New("connect-ip: request needs a host")
	}

	ctx := httpReq.Context()
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	body := newRequestBody()
	r := httpReq.Clone(streamCtx)
	r.Header[":protocol"] = []string{requestProtocol}
	r.Body = body
	rsp, err := c.roundTripper.RoundTrip(r)
	if !stop() {
		if err == nil {
			rsp.Body.Close()
		}
		err = context.Cause(ctx)
	}
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("connect-ip: failed to send request: %w", err)
	}
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		cancel()
		rsp.Body.Close()
		return nil, rsp, fmt.Errorf("connect-ip: server responded with %d", rsp.StatusCode)
	}
	return newProxiedConn(&http2Stream{
		reader: bufio.NewReader(rsp.Body),
		body:   body,
		rsp:    rsp.Body,
		cancel: cancel,
	}), rsp, nil
}

type http2Stream struct {
	reader *bufio.Reader
	body   *requestBody
	rsp    io.Closer
	cancel context.CancelFunc
}

func (s *http2Stream) Read(b []byte) (int, error)         { return s.reader.Read(b) }
func (s *http2Stream) ReadByte() (byte, error)            { return s.reader.ReadByte() }
func (s *http2Stream) Write(b []byte) (int, error)        { return s.body.Write(b) }
func (s *http2Stream) Close() error                       { return s.body.Close() }
func (s *http2Stream) CancelRead(quic.StreamErrorCode)    { s.abort() }
func (s *http2Stream) CancelWrite(quic.StreamErrorCode)   { s.abort() }
func (s *http2Stream) SetWriteDeadline(t time.Time) error { return s.body.SetWriteDeadline(t) }

func (s *http2Stream) abort() {
	s.cancel()
	s.body.CloseWithError(net.ErrClosed)
	s.rsp.Close()
}

type requestBody struct {
	mu       sync.Mutex
	cond     sync.Cond
	buf      []byte
	closed   bool
	err      error
	deadline time.Time
}

func newRequestBody() *requestBody {
	b := &requestBody{}
	b.cond.L = &b.mu
	return b
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for len(b.buf) == 0 && !b.closed && b.err == nil {
		b.cond.Wait()
	}
	if b.err != nil {
		return 0, b.err
	}
	if len(b.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	b.cond.Broadcast()
	return n, nil
}

func (b *requestBody) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		switch {
		case b.err != nil:
			return 0, b.err
		case b.closed:
			return 0, io.ErrClosedPipe
		case !b.deadline.IsZero() && !time.Now().Before(b.deadline):
			return 0, os.ErrDeadlineExceeded
		case len(b.buf) < maxBufferedRequestBody:
			b.buf = append(b.buf, p...)
			b.cond.Broadcast()
			return len(p), nil
		}
		b.cond.Wait()
	}
}

func (b *requestBody) Close() error {
	b.mu.Lock()
	b.closed = true
	b.cond.Broadcast()
	b.mu.Unlock()
	return nil
}

func (b *requestBody) CloseWithError(err error) {
	b.mu.Lock()
	if b.err == nil {
		b.err = err
		b.buf = nil
	}
	b.cond.Broadcast()
	b.mu.Unlock()
}

func (b *requestBody) SetWriteDeadline(t time.Time) error {
	b.mu.Lock()
	b.deadline = t
	b.cond.Broadcast()
	b.mu.Unlock()
	if d := time.Until(t); d > 0 {
		time.AfterFunc(d, func() {
			b.mu.Lock()
			b.cond.Broadcast()
			b.mu.Unlock()
		})
	}
	return nil
}
