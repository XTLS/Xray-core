package http

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	goerrors "errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is an HTTP proxy server.
type Server struct {
	config        *ServerConfig
	policyManager policy.Manager
}

// NewServer creates a new HTTP inbound handler.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		config:        config,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}

	return s, nil
}

func (s *Server) policy() policy.Session {
	config := s.config
	p := s.policyManager.ForLevel(config.UserLevel)
	return p
}

// Network implements proxy.Inbound.
func (*Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UNIX}
}

func isTimeout(err error) bool {
	nerr, ok := errors.Cause(err).(net.Error)
	return ok && nerr.Timeout()
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

type readerOnly struct {
	io.Reader
}

func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	return s.ProcessWithFirstbyte(ctx, network, conn, dispatcher)
}

// Firstbyte is for forwarded conn from SOCKS inbound
// Because it needs first byte to choose protocol
// We need to add it back
// Other parts are the same as the process function
func (s *Server) ProcessWithFirstbyte(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher, firstbyte ...byte) error {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "http"
	inbound.CanSpliceCopy = 2
	inbound.User = &protocol.MemoryUser{
		Level: s.config.UserLevel,
	}
	if !proxy.IsRAWTransportWithoutSecurity(conn) {
		inbound.CanSpliceCopy = 3
	}
	var reader *bufio.Reader
	if len(firstbyte) > 0 {
		readerWithoutFirstbyte := bufio.NewReaderSize(readerOnly{conn}, buf.Size)
		multiReader := io.MultiReader(bytes.NewReader(firstbyte), readerWithoutFirstbyte)
		reader = bufio.NewReaderSize(multiReader, buf.Size)
	} else {
		reader = bufio.NewReaderSize(readerOnly{conn}, buf.Size)
	}

Start:
	if err := conn.SetReadDeadline(time.Now().Add(s.policy().Timeouts.Handshake)); err != nil {
		errors.LogInfoInner(ctx, err, "failed to set read deadline")
	}

	request, err := http.ReadRequest(reader)
	if err != nil {
		return errors.New("failed to read http request").Base(err)
	}

	if len(s.config.Accounts) > 0 {
		user, pass, ok := parseBasicAuth(request.Header.Get("Proxy-Authorization"))
		if !ok || !s.config.HasAccount(user, pass) {
			return common.Error2(conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n")))
		}
		if inbound != nil {
			inbound.User.Email = user
		}
	}

	errors.LogInfo(ctx, "request to Method [", request.Method, "] Host [", request.Host, "] with URL [", request.URL, "]")
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		errors.LogDebugInner(ctx, err, "failed to clear read deadline")
	}

	defaultPort := net.Port(80)
	if strings.EqualFold(request.URL.Scheme, "https") {
		defaultPort = net.Port(443)
	}
	host := request.Host
	if host == "" {
		host = request.URL.Host
	}
	dest, err := http_proto.ParseHost(host, defaultPort)
	if err != nil {
		return errors.New("malformed proxy host: ", host).Base(err)
	}
	ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
		From:   conn.RemoteAddr(),
		To:     request.URL,
		Status: log.AccessAccepted,
		Reason: "",
		Email:  inbound.User.Email,
	})

	if strings.EqualFold(request.Method, "CONNECT") {
		return s.handleConnect(ctx, request, reader, conn, dest, dispatcher, inbound)
	}

	keepAlive := (strings.TrimSpace(strings.ToLower(request.Header.Get("Proxy-Connection"))) == "keep-alive")

	err = s.handlePlainHTTP(ctx, request, conn, dest, dispatcher)
	if err == errWaitAnother {
		if keepAlive {
			goto Start
		}
		err = nil
	}

	return err
}

func (s *Server) handleConnect(ctx context.Context, _ *http.Request, buffer *bufio.Reader, conn stat.Connection, dest net.Destination, dispatcher routing.Dispatcher, inbound *session.Inbound) error {
	_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		return errors.New("failed to write back OK response").Base(err)
	}

	reader := buf.NewReader(conn)
	if buffer.Buffered() > 0 {
		payload, err := buf.ReadFrom(io.LimitReader(buffer, int64(buffer.Buffered())))
		if err != nil {
			return err
		}
		reader = &buf.BufferedReader{Reader: reader, Buffer: payload}
		buffer = nil
	}

	if inbound.CanSpliceCopy == 2 {
		inbound.CanSpliceCopy = 1
	}
	if err := dispatcher.DispatchLink(
		ctx, dest, &transport.Link{
			Reader: reader,
			Writer: buf.NewWriter(conn),
		},
	); err != nil {
		return errors.New("failed to dispatch request").Base(err)
	}
	return nil
}

var errWaitAnother = errors.New("keep alive")

func (s *Server) handlePlainHTTP(ctx context.Context, request *http.Request, client net.Conn, dest net.Destination, dispatcher routing.Dispatcher) error {
	if !s.config.AllowTransparent && request.URL.Host == "" {
		// RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
		response := &http.Response{
			Status:        "Bad Request",
			StatusCode:    400,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header(make(map[string][]string)),
			Body:          nil,
			ContentLength: 0,
			Close:         true,
		}
		response.Header.Set("Proxy-Connection", "close")
		response.Header.Set("Connection", "close")
		return response.Write(client)
	}

	if len(request.URL.Host) > 0 {
		request.Host = request.URL.Host
	}
	http_proto.RemoveHopByHopHeaders(request.Header)

	// Prevent UA from being set to golang's default ones
	if request.Header.Get("User-Agent") == "" {
		request.Header.Set("User-Agent", "")
	}

	content := &session.Content{
		Protocol: "http/1.1",
	}

	content.SetAttribute(":method", strings.ToUpper(request.Method))
	content.SetAttribute(":path", request.URL.Path)
	for key := range request.Header {
		value := request.Header.Get(key)
		content.SetAttribute(strings.ToLower(key), value)
	}

	ctx = session.ContextWithContent(ctx, content)

	return forwardPlainHTTP(ctx, request, client, func(ctx context.Context, link *transport.Link) error {
		return dispatcher.DispatchLink(ctx, dest, link)
	})
}

// The HTTP codec owns the exchange. Request.Write emits the serialized request
// only as the route accepts it. The response parser consumes the outbound's
// buffers directly, with separate custody from the request body.
func forwardPlainHTTP(ctx context.Context, request *http.Request, client net.Conn, dispatch func(context.Context, *transport.Link) error) error {
	routeCtx, cancel := context.WithCancel(ctx)
	input := &httpRequestInput{
		ctx: routeCtx, data: make(chan buf.MultiBuffer), interrupted: make(chan struct{}),
	}
	output := newHTTPResponseOutput(routeCtx)
	request.Header.Set("Connection", "close")
	body := &httpRequestBody{ReadCloser: request.Body, remaining: request.ContentLength}
	if request.Body != nil && request.Body != http.NoBody {
		request.Body = body
	} else {
		body.consumed.Store(true)
	}

	sent := make(chan error, 1)
	go func() {
		writer := buf.NewBufferedWriter(input)
		common.Must(writer.SetBuffered(false))
		// Use net/http's header buffering. Its streamed-body path flushes
		// these headers before reading the body, including for Expect.
		sent <- request.Write(struct{ io.Writer }{Writer: writer})
	}()

	replied := make(chan error, 1)
	go func() {
		err := writePlainHTTPResponse(routeCtx, request, body, output, client)
		output.Interrupt()
		buf.ReleaseMulti(output.pending)
		replied <- err
	}()

	routeDone := make(chan error, 1)
	go func() {
		err := dispatch(routeCtx, &transport.Link{Reader: input, Writer: output})
		routeDone <- err
		output.Close()
		input.Interrupt()
	}()

	uploadDone, responseDone, reusable := false, false, false
	defer func() {
		cancel()
		output.Interrupt()
		if !reusable {
			client.Close()
		}
		if !uploadDone {
			<-sent
		}
		if !responseDone {
			<-replied
		}
	}()

	for {
		select {
		case err := <-sent:
			uploadDone = true
			if err != nil && !goerrors.Is(err, io.ErrClosedPipe) {
				return errors.New("failed to write whole request").Base(err)
			}
		case err := <-routeDone:
			if err != nil {
				return err
			}
		case result := <-replied:
			responseDone = true
			reusable = result == errWaitAnother
			return result
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

type httpRequestBody struct {
	io.ReadCloser
	remaining int64
	consumed  atomic.Bool
}

func (r *httpRequestBody) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.remaining -= int64(n)
	if r.remaining == 0 || err == io.EOF {
		r.consumed.Store(true)
	}
	return n, err
}

// httpRequestInput adapts the HTTP serializer to the selected outbound's
// demand. Only the serializer has an outstanding offer.
type httpRequestInput struct {
	ctx         context.Context
	data        chan buf.MultiBuffer
	interrupted chan struct{}
	stop        sync.Once

	mu      sync.Mutex
	bound   bool
	pending int64
	primary stats.Counter
	nested  []stats.Counter
}

func (r *httpRequestInput) WriteMultiBuffer(packets buf.MultiBuffer) error {
	size := int64(packets.Len())
	r.mu.Lock()
	if !r.bound {
		r.pending += size
	} else if r.primary != nil {
		r.primary.Add(size)
	}
	r.mu.Unlock()

	select {
	case r.data <- packets:
		return nil
	case <-r.interrupted:
	case <-r.ctx.Done():
	}
	buf.ReleaseMulti(packets)
	return io.ErrClosedPipe
}

func (r *httpRequestInput) SetUplinkCounter(counter stats.Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.bound {
		if counter != nil {
			r.nested = append(r.nested, counter)
		}
		return
	}
	r.bound = true
	r.primary = counter
	if counter != nil && r.pending != 0 {
		counter.Add(r.pending)
	}
	r.pending = 0
}

func (r *httpRequestInput) Interrupt() {
	r.stop.Do(func() { close(r.interrupted) })
}

func (r *httpRequestInput) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *httpRequestInput) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *httpRequestInput) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	select {
	case packets := <-r.data:
		size := int64(packets.Len())
		r.mu.Lock()
		for _, counter := range r.nested {
			counter.Add(size)
		}
		r.mu.Unlock()
		return packets, nil
	case <-timeout:
		return nil, buf.ErrReadTimeout
	case <-r.interrupted:
	case <-r.ctx.Done():
	}
	return nil, io.ErrClosedPipe
}

// httpResponseOutput gives the HTTP parser custody of decoded outbound
// buffers. Bounded response backlog keeps a multiplex carrier from waiting
// on a downstream write while the exchange still has room for its reply.
type httpResponseOutput struct {
	ctx   context.Context
	limit int32

	mu     sync.Mutex
	space  sync.Cond
	ready  *signal.Notifier
	closed bool
	queued buf.MultiBuffer

	pending buf.MultiBuffer // owned by the sole HTTP parser
}

func newHTTPResponseOutput(ctx context.Context) *httpResponseOutput {
	w := &httpResponseOutput{
		ctx: ctx, limit: policy.BufferPolicyFromContext(ctx).PerConnection, ready: signal.NewNotifier(),
	}
	w.space.L = &w.mu
	return w
}

func (w *httpResponseOutput) WriteMultiBuffer(packets buf.MultiBuffer) error {
	if packets.IsEmpty() {
		buf.ReleaseMulti(packets)
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for !w.closed && w.ctx.Err() == nil && w.limit >= 0 && w.queued.Len() > w.limit {
		w.space.Wait()
	}
	if w.closed || w.ctx.Err() != nil {
		buf.ReleaseMulti(packets)
		return io.ErrClosedPipe
	}
	w.queued, _ = buf.MergeMulti(w.queued, packets)
	w.ready.Signal()
	return nil
}

func (w *httpResponseOutput) Close() error {
	w.finish(false)
	return nil
}

func (w *httpResponseOutput) Interrupt() {
	w.finish(true)
}

func (w *httpResponseOutput) finish(discard bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	if discard {
		w.queued = buf.ReleaseMulti(w.queued)
	}
	w.ready.Signal()
	w.space.Broadcast()
}

func (w *httpResponseOutput) Read(p []byte) (int, error) {
	for w.pending.IsEmpty() {
		w.mu.Lock()
		w.pending, w.queued = w.queued, nil
		closed := w.closed
		w.space.Broadcast()
		w.mu.Unlock()
		if !w.pending.IsEmpty() {
			break
		}
		if closed {
			return 0, io.EOF
		}
		select {
		case <-w.ready.Wait():
		case <-w.ctx.Done():
			return 0, w.ctx.Err()
		}
	}
	var n int
	w.pending, n = buf.SplitBytes(w.pending, p)
	return n, nil
}

func writePlainHTTPResponse(ctx context.Context, request *http.Request, body *httpRequestBody, responseSource io.Reader, writer io.Writer) error {
	responseReader := bufio.NewReaderSize(responseSource, buf.Size)
	response, err := readResponseAndHandle100Continue(responseReader, request, writer)
	var result error
	if err == nil {
		http_proto.RemoveHopByHopHeaders(response.Header)
		if response.ContentLength >= 0 && body.consumed.Load() {
			response.Header.Set("Proxy-Connection", "keep-alive")
			response.Header.Set("Connection", "keep-alive")
			response.Header.Set("Keep-Alive", "timeout=60")
			response.Close = false
			result = errWaitAnother
		} else {
			response.Close = true
		}
		defer response.Body.Close()
	} else {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		errors.LogWarningInner(ctx, err, "failed to read response from ", request.Host)
		response = &http.Response{
			Status:        "Service Unavailable",
			StatusCode:    503,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header(make(map[string][]string)),
			Body:          nil,
			ContentLength: 0,
			Close:         true,
		}
		response.Header.Set("Connection", "close")
		response.Header.Set("Proxy-Connection", "close")
	}
	if err := response.Write(writer); err != nil {
		return errors.New("failed to write response").Base(err)
	}
	return result
}

// Sometimes, server might send 1xx response to client
// it should not be processed by http proxy handler, just forward it to client
func readResponseAndHandle100Continue(r *bufio.Reader, req *http.Request, writer io.Writer) (*http.Response, error) {
	// Wait for the HTTP/1.x status prefix before inspecting the buffered response.
	r.Peek(12)
	peekBytes, err := r.Peek(min(56, r.Buffered()))
	if err == nil || err == bufio.ErrBufferFull {
		str := string(peekBytes)
		ResponseLine := strings.Split(str, "\r\n")[0]
		_, status, _ := strings.Cut(ResponseLine, " ")
		// only handle 1xx response
		if strings.HasPrefix(status, "1") {
			ResponseHeader1xx := []byte{}
			// read until \r\n\r\n (end of http response header)
			for {
				data, err := r.ReadSlice('\n')
				if err != nil {
					return nil, errors.New("failed to read http 1xx response").Base(err)
				}
				ResponseHeader1xx = append(ResponseHeader1xx, data...)
				if len(ResponseHeader1xx) >= 4 && bytes.Equal(ResponseHeader1xx[len(ResponseHeader1xx)-4:], []byte{'\r', '\n', '\r', '\n'}) {
					break
				}
				if len(ResponseHeader1xx) > 1024 {
					return nil, errors.New("too big http 1xx response")
				}
			}
			writer.Write(ResponseHeader1xx)
		}
	}
	return http.ReadResponse(r, req)
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
