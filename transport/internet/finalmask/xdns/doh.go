package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/http2"
)

func NewDoHResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	endpoint, err := dohEndpoint(config, false)
	if err != nil {
		return nil, err
	}
	if dialer == nil || dialer.DialTCPContext == nil {
		return nil, fmt.Errorf("DoH requires a cancellable finalmask TCP dialer")
	}
	authority := dohAuthority(endpoint)
	dest, addr, err := resolverTarget(authority, config.Bootstrap, xnet.Network_TCP)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := resolverTLSConfig(config, endpoint.Hostname(), "h2")
	if err != nil {
		return nil, err
	}
	state := newDoHDialState()
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
		DisableCompression: true,
		StrictMaxConcurrentStreams: true,
		IdleConnTimeout: xnet.ConnIdleTimeout,
		WriteByteTimeout: resolverRequestTimeout,
		MaxHeaderListSize: 16 * 1024,
		DialTLSContext: func(ctx context.Context, network, target string, cfg *tls.Config) (net.Conn, error) {
			if network != "tcp" || !strings.EqualFold(target, authority) {
				return nil, fmt.Errorf("DoH dial changed HTTPS origin")
			}
			ctx, finish, err := state.dialContext(ctx)
			if err != nil {
				return nil, err
			}
			defer finish()
			conn, err := dialer.DialTCPContext(ctx, dest)
			if err != nil {
				return nil, err
			}
			if conn == nil {
				return nil, fmt.Errorf("DoH dialer returned no TCP connection")
			}
			owned := &dohTCPConn{Conn: conn, state: state}
			if err := state.add(owned); err != nil {
				return nil, err
			}
			secure := tls.Client(owned, cfg)
			if err := secure.HandshakeContext(ctx); err != nil {
				_ = secure.Close()
				return nil, err
			}
			negotiated := secure.ConnectionState()
			if negotiated.NegotiatedProtocol != "h2" || !negotiated.NegotiatedProtocolIsMutual {
				_ = secure.Close()
				return nil, fmt.Errorf("DoH server did not negotiate h2")
			}
			return secure, nil
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: rejectDoHRedirect}
	return newRequestResolver(addr, func(ctx context.Context, query []byte) ([]byte, error) {
		return exchangeDoH(ctx, client, endpoint.String(), query)
	}, func() {
		state.Close()
		transport.CloseIdleConnections()
	}), nil
}

func dohEndpoint(config *ResolverProto, h3 bool) (*url.URL, error) {
	if config == nil {
		return nil, fmt.Errorf("missing DoH resolver configuration")
	}
	u, err := url.Parse(config.Addr)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "https" && !(h3 && u.Scheme == "https+h3")) || u.Opaque != "" || u.Hostname() == "" || u.User != nil || strings.Contains(config.Addr, "#") || strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("invalid DoH HTTPS endpoint")
	}
	if config.ServerName != "" && !strings.EqualFold(config.ServerName, u.Hostname()) {
		return nil, fmt.Errorf("DoH serverName must match the HTTPS origin")
	}
	u.Scheme = "https"
	if u.Path == "" {
		u.Path = "/dns-query"
	}
	return u, nil
}

func dohAuthority(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func rejectDoHRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func exchangeDoH(ctx context.Context, client *http.Client, endpoint string, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > maxDNSMessageSize {
		return nil, fmt.Errorf("invalid DoH query length")
	}
	wire := bytes.Clone(query)
	wire[0], wire[1] = 0, 0
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	// Tunnel queries carry data and consume queues, so an already sent body cannot be replayed.
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/dns-message" {
		return nil, fmt.Errorf("invalid DoH response media type")
	}
	if resp.ContentLength >= 0 && (resp.ContentLength < 12 || resp.ContentLength > maxDNSMessageSize) {
		return nil, fmt.Errorf("invalid DoH response length %d", resp.ContentLength)
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(response) < 12 || len(response) > maxDNSMessageSize || (resp.ContentLength >= 0 && int64(len(response)) != resp.ContentLength) {
		return nil, fmt.Errorf("invalid DoH response length %d", len(response))
	}
	if response[0] != 0 || response[1] != 0 {
		return nil, fmt.Errorf("DoH response DNS ID is not zero")
	}
	response[0], response[1] = query[0], query[1]
	return response, nil
}

// HTTP transport dials can outlive the request that starts them.
type dohDialState struct {
	ctx context.Context
	cancel context.CancelFunc
	mu sync.Mutex
	wg sync.WaitGroup
	resources map[io.Closer]struct{}
}

func newDoHDialState() *dohDialState {
	ctx, cancel := context.WithCancel(context.Background())
	return &dohDialState{ctx: ctx, cancel: cancel, resources: make(map[io.Closer]struct{})}
}

func (s *dohDialState) dialContext(ctx context.Context) (context.Context, func(), error) {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, io.ErrClosedPipe
	}
	s.wg.Add(1)
	s.mu.Unlock()
	dialCtx, cancel := context.WithTimeout(ctx, resolverRequestTimeout)
	stop := context.AfterFunc(s.ctx, cancel)
	return dialCtx, func() { stop(); cancel(); s.wg.Done() }, nil
}

func (s *dohDialState) add(resource io.Closer) error {
	s.mu.Lock()
	if s.ctx.Err() != nil {
		s.mu.Unlock()
		_ = resource.Close()
		return io.ErrClosedPipe
	}
	s.resources[resource] = struct{}{}
	s.mu.Unlock()
	return nil
}

func (s *dohDialState) remove(resource io.Closer) {
	s.mu.Lock()
	delete(s.resources, resource)
	s.mu.Unlock()
}

func (s *dohDialState) Close() {
	s.cancel()
	s.mu.Lock()
	resources := make([]io.Closer, 0, len(s.resources))
	for resource := range s.resources {
		resources = append(resources, resource)
	}
	s.mu.Unlock()
	for _, resource := range resources {
		_ = resource.Close()
	}
	s.wg.Wait()
}

type dohTCPConn struct {
	net.Conn
	state *dohDialState
	once sync.Once
	err error
}

func (c *dohTCPConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.state.remove(c)
	})
	return c.err
}
