package masque

import (
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	go_errors "errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type Listener struct {
	path    pathMatcher
	addConn internet.ConnHandler
	ctx     context.Context
	cancel  context.CancelFunc

	quicServer   *http3.Server
	quicListener *quic.Listener
	transport    *quic.Transport
	pktConn      net.PacketConn
	tcpListener  net.Listener

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func serverVersions(config *tls.Config) (h2, h3 bool) {
	h2 = slices.Contains(config.NextProtocol, http2.NextProtoTLS)
	h3 = slices.Contains(config.NextProtocol, http3.NextProtoH3) || !h2
	return h2, h3
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, errors.New("address is domain")
	}
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, errors.New("tls config is nil")
	}
	config := streamSettings.ProtocolSettings.(*Config)
	path, err := newPathMatcher(config.Path)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		path:    path,
		addConn: handler,
		conns:   make(map[net.Conn]struct{}),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	h2, h3 := serverVersions(tlsConfig)
	if h3 {
		if err := l.listenHTTP3(address, port, streamSettings, tlsConfig); err != nil {
			l.Close()
			return nil, err
		}
		errors.LogInfo(ctx, "listening UDP for MASQUE over HTTP/3 on ", address, ":", port)
	}
	if h2 {
		if err := l.listenHTTP2(ctx, address, port, streamSettings, tlsConfig); err != nil {
			l.Close()
			return nil, err
		}
		errors.LogInfo(ctx, "listening TCP for MASQUE over HTTP/2 on ", address, ":", port)
	}
	return l, nil
}

func (l *Listener) listenHTTP3(address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, tlsConfig *tls.Config) error {
	quicParams := streamSettings.QuicParams
	if quicParams == nil {
		quicParams = &internet.QuicParams{
			BbrProfile: string(bbr.ProfileStandard),
		}
	}
	switch quicParams.Congestion {
	case "", "reno", "bbr", "brutal", "force-brutal":
	default:
		return errors.New("unknown congestion control: ", quicParams.Congestion)
	}
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     quicParams.InitStreamReceiveWindow,
		MaxStreamReceiveWindow:         quicParams.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: quicParams.InitConnReceiveWindow,
		MaxConnectionReceiveWindow:     quicParams.MaxConnReceiveWindow,
		MaxIdleTimeout:                 time.Duration(quicParams.MaxIdleTimeout) * time.Second,
		KeepAlivePeriod:                time.Duration(quicParams.KeepAlivePeriod) * time.Second,
		MaxIncomingStreams:             quicParams.MaxIncomingStreams,
		InitialPacketSize:              initialPacketSize,
		DisablePathMTUDiscovery:        quicParams.DisablePathMtuDiscovery || (runtime.GOOS != "linux" && runtime.GOOS != "windows" && runtime.GOOS != "darwin"),
		EnableDatagrams:                true,
		DisablePathManager:             true,
	}
	if quicParams.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = 30 * time.Second
	}

	udpAddr := &net.UDPAddr{IP: address.IP(), Port: int(port)}
	var err error
	if streamSettings.FinalMask != nil {
		l.pktConn, err = streamSettings.FinalMask.ListenPacket(context.Background(), udpAddr)
	} else {
		l.pktConn, err = internet.ListenSystemPacket(context.Background(), udpAddr, streamSettings.SocketSettings)
	}
	if err != nil {
		return errors.New("failed to listen UDP on ", address, ":", port).Base(err)
	}
	var resetKey *quic.StatelessResetKey
	if !quicParams.DisableStatelessReset {
		resetKey = &quic.StatelessResetKey{}
		common.Must2(rand.Read(resetKey[:]))
	}
	l.transport = &quic.Transport{Conn: l.pktConn, DisableGSO: quicParams.DisableGSO, StatelessResetKey: resetKey}

	gotlsConfig := tlsConfig.GetTLSConfig()
	gotlsConfig.NextProtos = []string{http3.NextProtoH3}
	l.quicListener, err = l.transport.Listen(gotlsConfig, quicConfig)
	if err != nil {
		return err
	}
	l.quicServer = &http3.Server{
		Handler:         l,
		EnableDatagrams: true,
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			switch quicParams.Congestion {
			case "reno":
			case "", "bbr", "brutal":
				congestion.UseBBR(conn, bbr.Profile(quicParams.BbrProfile))
			case "force-brutal":
				congestion.UseBrutal(conn, quicParams.BrutalUp, quicParams.BrutalDisableLossCompensation)
			}
			return context.WithValue(ctx, connAddrsKey{}, connAddrs{local: conn.LocalAddr(), remote: conn.RemoteAddr()})
		},
	}
	go func() {
		if err := l.quicServer.ServeListener(l.quicListener); err != nil && !go_errors.Is(err, quic.ErrServerClosed) && !go_errors.Is(err, http.ErrServerClosed) {
			errors.LogErrorInner(context.Background(), err, "failed to serve MASQUE over HTTP/3")
		}
	}()
	return nil
}

func (l *Listener) listenHTTP2(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, tlsConfig *tls.Config) error {
	tcpAddr := &net.TCPAddr{IP: address.IP(), Port: int(port)}
	var err error
	if streamSettings.FinalMask != nil {
		l.tcpListener, err = streamSettings.FinalMask.Listen(ctx, tcpAddr)
	} else {
		l.tcpListener, err = internet.ListenSystem(ctx, tcpAddr, streamSettings.SocketSettings)
	}
	if err != nil {
		return errors.New("failed to listen TCP on ", address, ":", port).Base(err)
	}
	gotlsConfig := tlsConfig.GetTLSConfig()
	gotlsConfig.NextProtos = []string{http2.NextProtoTLS}
	go l.acceptHTTP2(gotlsConfig)
	return nil
}

func (l *Listener) acceptHTTP2(config *gotls.Config) {
	for {
		conn, err := l.tcpListener.Accept()
		if err != nil {
			if l.ctx.Err() != nil || strings.Contains(err.Error(), "closed") {
				return
			}
			errors.LogWarningInner(context.Background(), err, "failed to accept MASQUE connections")
			if strings.Contains(err.Error(), "too many") {
				time.Sleep(500 * time.Millisecond)
			}
			continue
		}
		go l.serveHTTP2Conn(conn, config)
	}
}

func (l *Listener) serveHTTP2Conn(conn net.Conn, config *gotls.Config) {
	tlsConn := tls.Server(conn, config).(*tls.Conn)
	if !l.track(tlsConn, true) {
		tlsConn.Close()
		return
	}
	defer l.track(tlsConn, false)
	ctx, cancel := context.WithTimeout(l.ctx, http2HandshakeTimeout)
	err := tlsConn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		errors.LogDebugInner(context.Background(), err, "MASQUE: TLS handshake failed")
		tlsConn.Close()
		return
	}
	if protocol := tlsConn.NegotiatedProtocol(); protocol != http2.NextProtoTLS {
		errors.LogDebug(context.Background(), "MASQUE: the client negotiated ", protocol, " instead of h2")
		tlsConn.Close()
		return
	}
	serveHTTP2(l.ctx, tlsConn, l)
}

func (l *Listener) track(conn net.Conn, add bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !add {
		delete(l.conns, conn)
		return true
	}
	if l.ctx.Err() != nil {
		return false
	}
	l.conns[conn] = struct{}{}
	return true
}

func (l *Listener) Addr() net.Addr {
	if l.tcpListener != nil {
		return l.tcpListener.Addr()
	}
	return l.quicListener.Addr()
}

func (l *Listener) Close() error {
	l.cancel()
	var errs []error
	if l.quicServer != nil {
		errs = append(errs, l.quicServer.Close())
	}
	if l.quicListener != nil {
		errs = append(errs, l.quicListener.Close())
	}
	if l.transport != nil {
		errs = append(errs, l.transport.Close())
	}
	if l.pktConn != nil {
		errs = append(errs, l.pktConn.Close())
	}
	if l.tcpListener != nil {
		errs = append(errs, l.tcpListener.Close())
	}
	l.mu.Lock()
	for conn := range l.conns {
		conn.Close()
	}
	l.mu.Unlock()
	return errors.Combine(errs...)
}

func (l *Listener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !l.path.match(r.URL) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	request, err := connectip.ParseProxyRequest(r)
	if err != nil {
		status := http.StatusBadRequest
		if perr, ok := go_errors.AsType[*connectip.ProxyRequestParseError](err); ok {
			status = perr.HTTPStatus
		}
		w.WriteHeader(status)
		return
	}
	addrs, _ := r.Context().Value(connAddrsKey{}).(connAddrs)
	conn := &ServerConn{
		w:            w,
		request:      r,
		proxyRequest: request,
		local:        addrs.local,
		remote:       addrs.remote,
		done:         make(chan struct{}),
	}
	l.addConn(conn)
	select {
	case <-conn.done:
	case <-l.ctx.Done():
		conn.Close()
	}
}

type pathMatcher struct {
	path  string
	query url.Values
}

func newPathMatcher(path string) (pathMatcher, error) {
	u, err := url.ParseRequestURI(path)
	if err != nil || !strings.HasPrefix(u.Path, "/") {
		return pathMatcher{}, errors.New("invalid path: ", path)
	}
	return pathMatcher{path: u.Path, query: u.Query()}, nil
}

func (m pathMatcher) match(u *url.URL) bool {
	return u.Path == m.path && maps.EqualFunc(u.Query(), m.query, slices.Equal[[]string])
}

type ServerConn struct {
	w            http.ResponseWriter
	request      *http.Request
	proxyRequest *connectip.ProxyRequest
	local        net.Addr
	remote       net.Addr
	answer       sync.Once
	mu           sync.Mutex
	ipConn       *connectip.Conn
	done         chan struct{}
	closeOnce    sync.Once
}

func (c *ServerConn) Request() *http.Request {
	return c.request
}

func (c *ServerConn) Accept() (*connectip.Conn, error) {
	var err error = errors.New("the request was already answered")
	c.answer.Do(func() {
		var ipConn *connectip.Conn
		ipConn, err = (&connectip.Proxy{}).Proxy(c.w, c.proxyRequest)
		c.mu.Lock()
		c.ipConn = ipConn
		c.mu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	return c.ipConn, nil
}

func (c *ServerConn) Reject(status int, header http.Header) {
	c.answer.Do(func() {
		for k, vv := range header {
			for _, v := range vv {
				c.w.Header().Add(k, v)
			}
		}
		c.w.WriteHeader(status)
	})
}

func (c *ServerConn) tunnel() *connectip.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ipConn
}

func (c *ServerConn) Read(b []byte) (int, error) {
	ipConn := c.tunnel()
	if ipConn == nil {
		return 0, io.ErrClosedPipe
	}
	return ipConn.ReadPacket(b)
}

func (c *ServerConn) Write(b []byte) (int, error) {
	ipConn := c.tunnel()
	if ipConn == nil {
		return 0, io.ErrClosedPipe
	}
	icmp, err := ipConn.WritePacket(b)
	if err != nil {
		return 0, err
	}
	if len(icmp) > 0 {
		return 0, &PacketTooBigError{ICMP: icmp}
	}
	return len(b), nil
}

func (c *ServerConn) Close() error {
	c.closeOnce.Do(func() {
		c.Reject(http.StatusInternalServerError, nil)
		if ipConn := c.tunnel(); ipConn != nil {
			ipConn.Close()
		}
		close(c.done)
	})
	return nil
}

func (c *ServerConn) LocalAddr() net.Addr {
	return c.local
}

func (c *ServerConn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *ServerConn) SetDeadline(time.Time) error {
	return nil
}

func (c *ServerConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *ServerConn) SetWriteDeadline(time.Time) error {
	return nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
