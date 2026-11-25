package xdrive

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"github.com/xtls/xray-core/transport/internet/tls"
)

var errStalled = errors.New("the request made no progress")

type serviceTransport struct {
	plain  http.RoundTripper
	secure http.RoundTripper
	stall  time.Duration
}

// Cancel stalled requests, not long transfers that continue to make progress.
func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.plain
	if r.URL.Scheme == "https" {
		next = t.secure
	}

	ctx, cancel := context.WithCancelCause(r.Context())
	var timerMu sync.Mutex
	ended := false
	deadline := time.Now().Add(t.stall)
	timer := time.AfterFunc(t.stall, func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if !ended && !time.Now().Before(deadline) {
			cancel(errStalled)
		}
	})
	alive := func() {
		timerMu.Lock()
		defer timerMu.Unlock()
		if !ended {
			deadline = time.Now().Add(t.stall)
			timer.Reset(t.stall)
		}
	}
	end := func() {
		timerMu.Lock()
		ended = true
		timer.Stop()
		timerMu.Unlock()
		cancel(nil)
	}
	r = r.WithContext(ctx)
	// Clone before setting defaults: the caller owns the original headers.
	r.Header = r.Header.Clone()
	utils.TryDefaultHeadersWith(r.Header, "fetch")
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressBody{ReadCloser: r.Body, alive: alive, upload: true}
	}
	// Rewinds performed by the transport must also reset the stall timer.
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err != nil || body == http.NoBody {
				return body, err
			}
			return &progressBody{ReadCloser: body, alive: alive, upload: true}, nil
		}
	}

	resp, err := next.RoundTrip(r)
	if err != nil {
		err = stalled(ctx, err)
		end()
		return nil, err
	}
	alive()
	resp.Body = &progressBody{ReadCloser: resp.Body, alive: alive, end: end, ctx: ctx}
	return resp, nil
}

func (t *serviceTransport) CloseIdleConnections() {
	closeIdleTransport(t.plain)
	closeIdleTransport(t.secure)
}

func closeIdleTransport(t http.RoundTripper) {
	if closer, ok := t.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

// HTTP/2 can report the stall timeout as an ordinary cancellation.
func stalled(ctx context.Context, err error) error {
	if context.Cause(ctx) == errStalled {
		return errStalled
	}
	return err
}

type progressBody struct {
	io.ReadCloser
	alive  func()
	end    func()
	upload bool
	// ctx is that of the request, for the body of its response
	ctx context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	// Short upload reads keep the stall timer meaningful on slow connections.
	if b.upload {
		p = p[:min(len(p), 16<<10)]
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.alive()
	}
	if err != nil && err != io.EOF && b.ctx != nil {
		err = stalled(b.ctx, err)
	}
	return n, err
}

func (b *progressBody) Close() error {
	err := b.ReadCloser.Close()
	if b.end != nil {
		b.end()
	}
	return err
}

// connCtx owns sockets; h1Hosts shares ALPN observations between clients.
func newServiceClient(connCtx context.Context, h1Hosts *sync.Map, streamSettings *internet.MemoryStreamConfig, stall time.Duration, maxConns int) *http.Client {
	var (
		tlsConfig *tls.Config
		sockopt   *internet.SocketConfig
		fronting  *net.Destination
		// Detect silent h2 loss unless XMUX supplies an explicit keepalive.
		h2Idle, h2PingWait = 1500 * time.Millisecond, 2500 * time.Millisecond
		h3KeepAlive        time.Duration
	)
	if streamSettings != nil {
		tlsConfig = tls.ConfigFromStreamSettings(streamSettings)
		sockopt = streamSettings.SocketSettings
		fronting = streamSettings.Destination
		if config, ok := streamSettings.ProtocolSettings.(*Config); ok && config != nil && config.Xmux != nil {
			switch period := config.Xmux.HKeepAlivePeriod; {
			case period > 0:
				h3KeepAlive = time.Duration(period) * time.Second
				h2Idle, h2PingWait = h3KeepAlive, 0
			case period < 0:
				h2Idle, h2PingWait = 0, 0
			}
		}
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint)

	// A configured front replaces the address, not the transport network.
	dial := func(ctx context.Context, network, addr string) (net.Conn, net.Destination, error) {
		ctx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(connCtx, cancel)
		defer stop()
		defer cancel()
		if err := connCtx.Err(); err != nil {
			return nil, net.Destination{}, err
		}
		host, err := net.ParseDestination(network + ":" + addr)
		if err != nil {
			return nil, host, errors.New("bad address: ", addr).Base(err)
		}

		target := host
		if fronting != nil {
			target.Address = fronting.Address
			if fronting.Port != 0 {
				target.Port = fronting.Port
			}
		}

		var conn net.Conn
		switch {
		case streamSettings == nil || streamSettings.FinalMask == nil:
			conn, err = internet.DialSystem(ctx, target, sockopt)
		case target.Network == net.Network_UDP:
			conn, err = streamSettings.FinalMask.DialUDP(ctx, target)
		default:
			conn, err = streamSettings.FinalMask.DialTCP(ctx, target)
		}
		if err != nil {
			return nil, host, errors.New("failed to dial to dest").Base(err)
		}
		// HTTP/3 must close QUIC itself as well as its UDP socket.
		if network == "udp" {
			return conn, host, nil
		}
		// A recently canceled h2 stream may still own the socket.
		stopConn := context.AfterFunc(connCtx, func() { conn.Close() })
		return &ctxConn{Conn: conn, stop: stopConn}, host, nil
	}

	dialPlain := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, _, err := dial(ctx, "tcp", addr)
		return conn, err
	}

	// http.Transport picks h2 or h1 by the ALPN in the ConnectionState of the conn
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, host, err := dial(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}

		gotlsConfig := tlsConfig.GetTLSConfig(tls.WithDestination(host))
		var tlsConn net.Conn
		if fingerprint == nil {
			tlsConn = tls.Client(conn, gotlsConfig)
		} else {
			tlsConn = tls.UClient(conn, gotlsConfig, fingerprint)
		}
		// Bound the handshake independently of connection reuse.
		ctx, cancel := context.WithTimeout(ctx, stall)
		defer cancel()
		if err := tlsConn.(tls.Interface).HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	secure := func(connsPerHost int) *http.Transport {
		return &http.Transport{
			DialTLSContext:      dialTLS,
			ForceAttemptHTTP2:   true,
			IdleConnTimeout:     net.ConnIdleTimeout,
			MaxIdleConns:        maxConns,
			MaxIdleConnsPerHost: maxConns,
			MaxConnsPerHost:     connsPerHost,
			HTTP2:               &http.HTTP2Config{SendPingTimeout: h2Idle, PingTimeout: h2PingWait},
		}
	}

	var https http.RoundTripper = &secureTransport{h2: secure(1), h1: secure(maxConns), h1Hosts: h1Hosts}
	// no server offers h3 by ALPN over TCP, so it is used only when asked for alone
	if slices.Equal(tlsConfig.NextProtocol, []string{"h3"}) {
		quicParams := streamSettings.QuicParams
		if quicParams == nil {
			quicParams = &internet.QuicParams{BbrProfile: string(bbr.ProfileStandard)}
		}
		// QUIC idle timeout and connCtx bound unused connections.
		quicConfig := &quic.Config{
			InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
			MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
			InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
			MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
			MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
			KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
			MaxIncomingStreams:             quicParams.MaxIncomingStreams,
			DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
			ChromeParrot:                   !quicParams.DisableChromeParrot,
		}
		if quicConfig.KeepAlivePeriod == 0 {
			quicConfig.KeepAlivePeriod = h3KeepAlive
		}

		https = &http3.Transport{
			QUICConfig: quicConfig,
			Dial: func(ctx context.Context, addr string, _ *gotls.Config, cfg *quic.Config) (*quic.Conn, error) {
				ctx, cancel := context.WithCancel(ctx)
				stop := context.AfterFunc(connCtx, cancel)
				defer stop()
				defer cancel()
				if connCtx.Err() != nil {
					cancel()
				}
				switch quicParams.Congestion {
				case "", "bbr", "reno":
				default:
					return nil, errors.New("unsupported congestion control over h3: ", quicParams.Congestion)
				}

				conn, host, err := dial(ctx, "udp", addr)
				if err != nil {
					return nil, err
				}
				var pktConn net.PacketConn
				var udpAddr net.Addr
				switch c := conn.(type) {
				case *net.PacketConnWrapper:
					pktConn = c.PacketConn
					udpAddr = c.RemoteAddr()
				case *cnc.Connection:
					pktConn = &internet.FakePacketConn{Conn: c}
					udpAddr = &net.UDPAddr{IP: []byte{0, 0, 0, 0}}
				default:
					conn.Close()
					return nil, errors.New("failed to dial to dest: unexpected ", reflect.TypeOf(c))
				}

				// Set SNI before certificate pinning and ECH lookup.
				gotlsConfig := tlsConfig.GetTLSConfig(tls.WithDestination(host))
				// it is for servers, and ChromeParrot refuses a config that has it
				gotlsConfig.GetCertificate = nil
				tr := &quic.Transport{Conn: pktConn, DisableGSO: quicParams.DisableGSO}
				if !quicParams.DisableChromeParrot {
					tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
				}
				qconn, err := tr.Dial(ctx, udpAddr, gotlsConfig, cfg)
				if err != nil {
					tr.Close()
					pktConn.Close()
					return nil, err
				}
				stopConn := context.AfterFunc(connCtx, func() { qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
				context.AfterFunc(qconn.Context(), func() { stopConn(); tr.Close(); pktConn.Close() })
				if quicParams.Congestion != "reno" {
					congestion.UseBBR(qconn, bbr.Profile(quicParams.BbrProfile))
				}
				return qconn, nil
			},
		}
	}

	return &http.Client{
		Transport: &serviceTransport{
			plain: &http.Transport{
				DialContext:         dialPlain,
				IdleConnTimeout:     net.ConnIdleTimeout,
				MaxIdleConns:        maxConns,
				MaxIdleConnsPerHost: maxConns,
				MaxConnsPerHost:     maxConns,
			},
			secure: https,
			stall:  stall,
		},
	}
}

// Closing the socket unregisters the owner-context callback.
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// Use one h2 connection per host, but allow parallel h1 connections.
type secureTransport struct {
	h2, h1  http.RoundTripper
	h1Hosts *sync.Map
}

func (t *secureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if _, ok := t.h1Hosts.Load(r.URL.Host); ok {
		return t.h1.RoundTrip(r)
	}
	resp, err := t.h2.RoundTrip(r)
	if err == nil && resp.ProtoMajor == 1 {
		t.h1Hosts.Store(r.URL.Host, true)
	}
	return resp, err
}

func (t *secureTransport) CloseIdleConnections() {
	closeIdleTransport(t.h2)
	closeIdleTransport(t.h1)
}

var errSessionClosed = errors.New("the session is closed")

// XMUX selects a lease once, not repeatedly while looking for a connection.
// Running references cover both the session and any response bodies still open.
type connPool struct {
	mu     sync.Mutex
	mux    *splithttp.XmuxManager
	media  []*splithttp.XmuxManager // Drive-only, one connection per round-robin lane
	next   int
	ctx    context.Context
	cancel context.CancelFunc
}

type poolConn struct {
	transport http.RoundTripper
	ctx       context.Context
	cancel    context.CancelFunc
	stop      func() bool
}

func (c *poolConn) IsClosed() bool { return c.ctx.Err() != nil }

func (c *poolConn) Close() error {
	c.cancel()
	c.stop()
	closeIdleTransport(c.transport)
	return nil
}

// driveMediaConns is the number of Drive media connections: XMUX
// maxConnections when set, else 4. One Google connection carries only a
// fraction of a link, so media requests are spread over these.
func driveMediaConns(x *splithttp.XmuxConfig) int32 {
	if x != nil && x.MaxConnections != nil && x.MaxConnections.To > 0 {
		return x.MaxConnections.To
	}
	return 4
}

// Positive conns gives Drive round-robin lanes; other backends keep one manager.
func newConnPool(config *splithttp.XmuxConfig, conns int32, newClient func(context.Context) *http.Client) *connPool {
	if config == nil {
		config = &splithttp.XmuxConfig{}
	}
	maxConns := config.MaxConnections
	if conns > 0 {
		maxConns = &splithttp.RangeConfig{From: 1, To: 1}
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &connPool{ctx: ctx, cancel: cancel}
	newConn := func() splithttp.XmuxConn {
		ctx, cancel := context.WithCancel(p.ctx)
		c := &poolConn{ctx: ctx, cancel: cancel, transport: newClient(ctx).Transport}
		c.stop = context.AfterFunc(ctx, func() { closeIdleTransport(c.transport) })
		return c
	}
	newMux := func() *splithttp.XmuxManager {
		return splithttp.NewXmuxManager(splithttp.XmuxConfig{
			MaxConnections: maxConns, MaxConcurrency: config.MaxConcurrency,
			CMaxReuseTimes: config.CMaxReuseTimes, HMaxRequestTimes: config.HMaxRequestTimes,
			HMaxReusableSecs: config.HMaxReusableSecs, HKeepAlivePeriod: config.HKeepAlivePeriod,
		}, newConn)
	}
	p.mux = newMux()
	for i := int32(0); i < conns; i++ {
		mux := p.mux
		if i > 0 {
			mux = newMux()
		}
		p.media = append(p.media, mux)
	}
	return p
}

func (p *connPool) Close() {
	if p != nil {
		p.cancel()
	}
}

type sessionTransport struct {
	pool   *connPool
	client *splithttp.XmuxClient // guarded by pool.mu
	closed bool
	// spread selects a pool connection per request instead of pinning one.
	spread bool
}

func (t *sessionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	p := t.pool
	p.mu.Lock()
	if t.closed || p.ctx.Err() != nil || r.Context().Err() != nil {
		p.mu.Unlock()
		if r.Body != nil {
			r.Body.Close()
		}
		if err := r.Context().Err(); err != nil {
			return nil, err
		}
		return nil, errSessionClosed
	}
	c := t.client
	if t.spread {
		mux := p.mux
		if len(p.media) != 0 {
			mux = p.media[p.next]
			p.next = (p.next + 1) % len(p.media)
		}
		c = mux.GetXmuxClient(r.Context())
	} else if c == nil || c.XmuxConn.IsClosed() || c.LeftRequests.Load() <= 0 || (!c.UnreusableAt.IsZero() && time.Now().After(c.UnreusableAt)) {
		if c != nil {
			c.DoneRunning()
		}
		c = p.mux.GetXmuxClient(r.Context())
		c.AddRunning()
		t.client = c
	}
	c.LeftRequests.Add(-1)
	c.AddRunning()
	p.mu.Unlock()
	resp, err := c.XmuxConn.(*poolConn).transport.RoundTrip(r)
	if err != nil {
		c.DoneRunning()
		return nil, err
	}
	resp.Body = &leasedBody{ReadCloser: resp.Body, release: sync.OnceFunc(c.DoneRunning)}
	return resp, nil
}

type leasedBody struct {
	io.ReadCloser
	release func()
}

func (b *leasedBody) Close() error {
	defer b.release()
	return b.ReadCloser.Close()
}

func (t *sessionTransport) Close() {
	t.pool.mu.Lock()
	defer t.pool.mu.Unlock()
	t.closed = true
	if t.client != nil {
		t.client.DoneRunning()
		t.client = nil
	}
}
