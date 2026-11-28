package dns

import (
	"context"
	"encoding/binary"
	"io"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

// TCPNameServer implemented DNS over TCP (RFC7766).
type TCPNameServer struct {
	cacheController *CacheController
	destination     *net.Destination
	reqID           uint32
	exchange        func(context.Context, []byte) ([]byte, error)
	clientIP        net.IP
}

// NewTCPNameServer creates DNS over TCP server object for remote resolving.
func NewTCPNameServer(
	url *url.URL,
	dispatcher routing.Dispatcher,
	disableCache bool, serveStale bool, serveExpiredTTL uint32,
	clientIP net.IP,
) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCP", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}

	s.exchange = func(ctx context.Context, request []byte) ([]byte, error) {
		return s.exchangeRouted(ctx, request, dispatcher)
	}

	errors.LogInfo(context.Background(), "DNS: created TCP client initialized for ", url.String())
	return s, nil
}

// NewTCPLocalNameServer creates DNS over TCP client object for local resolving
func NewTCPLocalNameServer(url *url.URL, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	s, err := baseTCPNameServer(url, "TCPL", disableCache, serveStale, serveExpiredTTL, clientIP)
	if err != nil {
		return nil, err
	}

	s.exchange = s.exchangeLocal

	errors.LogInfo(context.Background(), "DNS: created Local TCP client initialized for ", url.String())
	return s, nil
}

func baseTCPNameServer(url *url.URL, prefix string, disableCache bool, serveStale bool, serveExpiredTTL uint32, clientIP net.IP) (*TCPNameServer, error) {
	port := net.Port(53)
	if url.Port() != "" {
		var err error
		if port, err = net.PortFromString(url.Port()); err != nil {
			return nil, err
		}
	}
	dest := net.TCPDestination(net.ParseAddress(url.Hostname()), port)

	s := &TCPNameServer{
		cacheController: NewCacheController(prefix+"//"+dest.NetAddr(), disableCache, serveStale, serveExpiredTTL),
		destination:     &dest,
		clientIP:        clientIP,
	}

	return s, nil
}

// Name implements Server.
func (s *TCPNameServer) Name() string {
	return s.cacheController.name
}

// IsDisableCache implements Server.
func (s *TCPNameServer) IsDisableCache() bool {
	return s.cacheController.disableCache
}

func (s *TCPNameServer) newReqID() uint16 {
	return uint16(atomic.AddUint32(&s.reqID, 1))
}

// getCacheController implements CachedNameserver.
func (s *TCPNameServer) getCacheController() *CacheController {
	return s.cacheController
}

// sendQuery implements CachedNameserver.
func (s *TCPNameServer) sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns_feature.IPOption) {
	errors.LogInfo(ctx, s.Name(), " querying DNS for: ", fqdn)

	reqs, err := buildReqMsgs(fqdn, option, s.newReqID, genEDNS0Options(s.clientIP, 0))
	if err != nil {
		errors.LogErrorInner(ctx, err, "failed to build dns query for ", fqdn)
		if noResponseErrCh != nil {
			if option.IPv4Enable {
				noResponseErrCh <- err
			}
			if option.IPv6Enable {
				noResponseErrCh <- err
			}
		}
		return
	}

	var deadline time.Time
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	} else {
		deadline = time.Now().Add(time.Second * 5)
	}

	for _, req := range reqs {
		go func(r *dnsRequest) {
			dnsCtx := ctx

			if inbound := session.InboundFromContext(ctx); inbound != nil {
				dnsCtx = session.ContextWithInbound(dnsCtx, inbound)
			}

			dnsCtx = session.ContextWithContent(dnsCtx, &session.Content{
				Protocol:       "dns",
				SkipDNSResolve: true,
			})

			var cancel context.CancelFunc
			dnsCtx, cancel = context.WithDeadline(dnsCtx, deadline)
			defer cancel()

			request, err := r.msg.AppendPack(make([]byte, 2, 512))
			if err == nil && len(request) > buf.Size {
				err = buf.ErrBufferFull
			}
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to pack DNS TCP query")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			binary.BigEndian.PutUint16(request[:2], uint16(len(request)-2))

			response, err := s.exchange(dnsCtx, request)
			if err != nil {
				errors.LogErrorInner(ctx, err, "DNS TCP exchange failed")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}
			rec, err := parseResponse(response)
			if err != nil {
				errors.LogErrorInner(ctx, err, "failed to parse DNS over TCP response")
				if noResponseErrCh != nil {
					noResponseErrCh <- err
				}
				return
			}

			s.cacheController.updateRecord(r, rec)
		}(req)
	}
}

func (s *TCPNameServer) exchangeLocal(ctx context.Context, request []byte) ([]byte, error) {
	conn, err := internet.DialSystem(ctx, *s.destination, nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	if err := buf.WriteAllBytes(conn, request, nil); err != nil {
		return nil, err
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	body, err := tcpDNSResponseBody(prefix)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (s *TCPNameServer) exchangeRouted(ctx context.Context, request []byte, dispatcher routing.Dispatcher) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// ctx is the shared DNS request, not an individual route's lookup waiter.
	deadline, _ := ctx.Deadline()
	routeCtx, cancel := context.WithDeadline(toDnsContext(ctx, s.destination.String()), deadline)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()

	readCtx, stopRead := context.WithCancel(routeCtx)
	defer stopRead()
	input := &tcpDNSQueryReader{ctx: readCtx, cancel: stopRead, request: request}
	response := make(chan tcpDNSResponse, 1)
	output := &tcpDNSResponseWriter{ctx: routeCtx, response: response}
	go func() {
		link := &transport.Link{Reader: input, Writer: output}
		if err := dispatcher.DispatchLink(routeCtx, *s.destination, link); err != nil {
			output.finish(err)
		}
		// The selected outbound owns the writer lifetime. A multiplexed
		// outbound can return while its carrier finishes a response write.
	}()
	var result tcpDNSResponse
	select {
	case result = <-response:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-routeCtx.Done():
		result.err = routeCtx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return result.body, result.err
}

type tcpDNSQueryReader struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu           sync.Mutex
	request      []byte
	counterBound bool
	counters     []stats.Counter
}

func (r *tcpDNSQueryReader) SetUplinkCounter(counter stats.Counter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.counterBound {
		r.counterBound = true
		if counter != nil {
			counter.Add(int64(len(r.request)))
		}
	} else if counter != nil {
		r.counters = append(r.counters, counter)
	}
}

func (r *tcpDNSQueryReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.read(nil)
}

func (r *tcpDNSQueryReader) ReadMultiBufferTimeout(timeout time.Duration) (buf.MultiBuffer, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	return r.read(timer.C)
}

func (r *tcpDNSQueryReader) read(timeout <-chan time.Time) (buf.MultiBuffer, error) {
	r.mu.Lock()
	if err := r.ctx.Err(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	request := r.request
	r.request = nil
	for _, counter := range r.counters {
		counter.Add(int64(len(request)))
	}
	r.mu.Unlock()
	if request != nil {
		return buf.MultiBuffer{buf.FromBytes(request)}, nil
	}
	select {
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	case <-timeout:
		return nil, buf.ErrReadTimeout
	}
}

func (r *tcpDNSQueryReader) Interrupt() { r.cancel() }

type tcpDNSResponse struct {
	body []byte
	err  error
}

func tcpDNSResponseBody(prefix [2]byte) ([]byte, error) {
	size := binary.BigEndian.Uint16(prefix[:])
	if size > buf.Size {
		return nil, errors.New("DNS TCP response exceeds buffer size: ", size)
	}
	return make([]byte, size), nil
}

// tcpDNSResponseWriter assembles one length-prefixed response. Only the complete
// body reaches the cache; the prefix bounds allocation and can span buffers.
type tcpDNSResponseWriter struct {
	ctx      context.Context
	response chan<- tcpDNSResponse

	mu          sync.Mutex
	prefix      [2]byte
	prefixBytes int
	body        []byte
	bodyBytes   int
	finished    bool
}

func (w *tcpDNSResponseWriter) WriteMultiBuffer(packets buf.MultiBuffer) error {
	defer buf.ReleaseMulti(packets)
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.ctx.Err(); err != nil {
		return err
	}
	if w.finished {
		return io.ErrClosedPipe
	}
	for _, packet := range packets {
		data := packet.Bytes()
		if w.prefixBytes < len(w.prefix) {
			n := copy(w.prefix[w.prefixBytes:], data)
			w.prefixBytes += n
			if w.prefixBytes < len(w.prefix) {
				continue
			}
			data = data[n:]
			body, err := tcpDNSResponseBody(w.prefix)
			if err != nil {
				w.complete(tcpDNSResponse{err: err})
				return err
			}
			w.body = body
		}
		w.bodyBytes += copy(w.body[w.bodyBytes:], data)
		if w.bodyBytes == len(w.body) {
			w.complete(tcpDNSResponse{body: w.body})
			return nil
		}
	}
	return nil
}

func (w *tcpDNSResponseWriter) finish(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.complete(tcpDNSResponse{err: err})
}

func (w *tcpDNSResponseWriter) complete(result tcpDNSResponse) {
	if !w.finished {
		w.finished = true
		w.body = nil
		w.response <- result
	}
}

func (w *tcpDNSResponseWriter) Close() error {
	w.finish(io.ErrUnexpectedEOF)
	return nil
}

func (w *tcpDNSResponseWriter) Interrupt() { w.finish(io.ErrClosedPipe) }

// QueryIP implements Server.
func (s *TCPNameServer) QueryIP(ctx context.Context, domain string, option dns_feature.IPOption) ([]net.IP, uint32, error) {
	return queryIP(ctx, s, domain, option)
}
