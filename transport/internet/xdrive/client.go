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

// RoundTrip ends a request that stands still for t.stall, with no answer that
// long after its body went out or no byte of either body, but not one that just
// runs long: a large object on a slow link takes minutes and is fine as long as
// its bytes move
func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	next := t.plain
	if r.URL.Scheme == "https" {
		next = t.secure
	}

	ctx, cancel := context.WithCancelCause(r.Context())
	timer := time.AfterFunc(t.stall, func() { cancel(errStalled) })
	alive := func() { timer.Reset(t.stall) }
	end := func() {
		timer.Stop()
		cancel(nil)
	}
	r = r.WithContext(ctx)
	// the headers of chrome as with XHTTP and DoH, net/http and http3 would send
	// their own user agent after a hello of chrome
	r.Header = r.Header.Clone()
	utils.TryDefaultHeadersWith(r.Header, "fetch")
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = &progressBody{ReadCloser: r.Body, alive: alive}
	}
	// a body sent again by the transport itself, after a GOAWAY or on a reused
	// connection that failed, moves just the same
	if getBody := r.GetBody; getBody != nil {
		r.GetBody = func() (io.ReadCloser, error) {
			body, err := getBody()
			if err != nil || body == http.NoBody {
				return body, err
			}
			return &progressBody{ReadCloser: body, alive: alive}, nil
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

// stalled returns errStalled for an error that the stall gave, which http2 reports
// as a plain cancel
func stalled(ctx context.Context, err error) error {
	if context.Cause(ctx) == errStalled {
		return errStalled
	}
	return err
}

type progressBody struct {
	io.ReadCloser
	alive func()
	end   func()
	// ctx is that of the request, for the body of its response
	ctx context.Context
}

func (b *progressBody) Read(p []byte) (int, error) {
	// http2 reads a request body up to 512 KiB at a time and sends it all before
	// the next read, which on a slow link could look like no progress
	n, err := b.ReadCloser.Read(p[:min(len(p), 16<<10)])
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

// newServiceClient returns a client whose requests end after stall without
// progress, see serviceTransport.RoundTrip, and whose connections close when
// connCtx is done. Clients that share h1Hosts share which hosts answer over h1
func newServiceClient(connCtx context.Context, h1Hosts *sync.Map, streamSettings *internet.MemoryStreamConfig, stall time.Duration, maxConns int) *http.Client {
	var (
		tlsConfig *tls.Config
		sockopt   *internet.SocketConfig
		fronting  *net.Destination
		keepAlive = net.ChromeH2KeepAlivePeriod
		// h3 keeps alive only when asked to, see below
		h3KeepAlive time.Duration
	)
	if streamSettings != nil {
		tlsConfig = tls.ConfigFromStreamSettings(streamSettings)
		sockopt = streamSettings.SocketSettings
		fronting = streamSettings.Destination
		if config, ok := streamSettings.ProtocolSettings.(*Config); ok && config.Xmux != nil {
			switch period := config.Xmux.HKeepAlivePeriod; {
			case period > 0:
				keepAlive = time.Duration(period) * time.Second
				h3KeepAlive = keepAlive
			case period < 0:
				keepAlive = 0
			}
		}
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint)

	// fronting takes only the address and port, the network stays that of the
	// dial, which is UDP for h3 though the destination is built as TCP
	dial := func(ctx context.Context, network, addr string) (net.Conn, net.Destination, error) {
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
		case streamSettings.FinalMask == nil:
			conn, err = internet.DialSystem(ctx, target, sockopt)
		case target.Network == net.Network_UDP:
			conn, err = streamSettings.FinalMask.DialUDP(ctx, target)
		default:
			conn, err = streamSettings.FinalMask.DialTCP(ctx, target)
		}
		if err != nil {
			return nil, host, errors.New("failed to dial to dest").Base(err)
		}
		// h3 closes its QUIC connection instead, as the server never hears of a UDP
		// socket that closes
		if network == "udp" {
			return conn, host, nil
		}
		// CloseIdleConnections leaves an h2 connection open while a stream just
		// canceled has not left it yet
		stop := context.AfterFunc(connCtx, func() { conn.Close() })
		return &ctxConn{Conn: conn, stop: stop}, host, nil
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
		// the dial outlives the request that started it, and a handshake that hangs
		// would keep the one connection of the host to itself
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
			HTTP2:               &http.HTTP2Config{SendPingTimeout: keepAlive},
		}
	}

	var https http.RoundTripper = &secureTransport{h2: secure(1), h1: secure(maxConns), h1Hosts: h1Hosts}
	// no server offers h3 by ALPN over TCP, so it is used only when asked for alone
	if slices.Equal(tlsConfig.NextProtocol, []string{"h3"}) {
		quicParams := streamSettings.QuicParams
		if quicParams == nil {
			quicParams = &internet.QuicParams{BbrProfile: string(bbr.ProfileStandard)}
		}
		// the defaults are those of quic-go, with no keepalive unless asked for, as
		// in DoH: http3 never closes a connection that is idle or that it dropped
		// after an error, so only the idle timeout or the end of connCtx ends it
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
				switch quicParams.Congestion {
				case "", "bbr", "reno":
				default:
					// brutal is for Hysteria servers, not services, and a panic here, in
					// a goroutine of http3, would end the process
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

				// built for each dial with the host as SNI, as for h2: http3 sets the
				// SNI on a copy, which a pinned CA and the ECH lookup do not see
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
				stop := context.AfterFunc(connCtx, func() { qconn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeNoError), "") })
				context.AfterFunc(qconn.Context(), func() { stop(); tr.Close(); pktConn.Close() })
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

// ctxConn is a connection that connCtx no longer closes once it is closed,
// so that one that ends on its own leaves nothing behind in connCtx
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// secureTransport keeps a host to one connection, all that h2 needs, as without
// a limit parallel requests would each dial their own. A host that answers over
// h1 moves to a transport with more, since h1 carries one request at a time
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

var errSessionClosed = errors.New("the session is closed")

// connPool hands the sessions of a storage the connections of XMUX, each a
// client of its own made by newClient
type connPool struct {
	mu   sync.Mutex
	xmux *splithttp.XmuxManager
}

func newConnPool(config *splithttp.XmuxConfig, newClient func(connCtx context.Context) *http.Client) *connPool {
	var xmuxConfig splithttp.XmuxConfig
	if config != nil {
		xmuxConfig = *config
	}
	return &connPool{xmux: splithttp.NewXmuxManager(xmuxConfig, func() splithttp.XmuxConn {
		ctx, cancel := context.WithCancel(context.Background())
		return &poolConn{next: newClient(ctx).Transport, cancel: cancel}
	})}
}

// poolConn is a connection of XMUX, which closes once XMUX drops it and the
// requests on it end
type poolConn struct {
	next   http.RoundTripper
	cancel context.CancelFunc

	mu       sync.Mutex
	inflight int
	closing  bool
}

func (c *poolConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing
}

func (c *poolConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closing = true
	if c.inflight == 0 {
		c.cancel()
	}
	return nil
}

func (c *poolConn) done() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inflight--
	if c.closing && c.inflight == 0 {
		c.cancel()
	}
}

// roundTrip sends a request counted in inflight by the caller
func (c *poolConn) roundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.next.RoundTrip(r)
	if err != nil {
		c.done()
		return nil, err
	}
	resp.Body = &doneBody{ReadCloser: resp.Body, done: sync.OnceFunc(c.done)}
	return resp, nil
}

type doneBody struct {
	io.ReadCloser
	done func()
}

func (b *doneBody) Close() error {
	err := b.ReadCloser.Close()
	b.done()
	return err
}

// sessionTransport sends the requests of one session over a connection of
// XMUX, and over another once that one has no requests or time left
type sessionTransport struct {
	pool *connPool

	mu     sync.Mutex
	client *splithttp.XmuxClient
	closed bool
}

func (t *sessionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errSessionClosed
	}
	client := t.client
	if client == nil || client.LeftRequests.Add(-1) < 0 || !client.UnreusableAt.IsZero() && time.Now().After(client.UnreusableAt) {
		t.pool.mu.Lock()
		t.client = t.pool.xmux.GetXmuxClient(r.Context())
		t.pool.mu.Unlock()
		t.client.AddRunning()
		t.client.LeftRequests.Add(-1)
		if client != nil {
			client.DoneRunning()
		}
		client = t.client
	}
	// counted under mu, or another request of the session that moves on could
	// close the connection before this one is sent
	conn := client.XmuxConn.(*poolConn)
	conn.mu.Lock()
	conn.inflight++
	conn.mu.Unlock()
	t.mu.Unlock()
	return conn.roundTrip(r)
}

func (t *sessionTransport) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.client != nil {
		t.client.DoneRunning()
		t.client = nil
	}
}
