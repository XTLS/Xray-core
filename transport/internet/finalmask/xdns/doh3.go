package xdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

func NewDoH3Resolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	endpoint, err := dohEndpoint(config, true)
	if err != nil {
		return nil, err
	}
	if dialer == nil || dialer.DialUDPContext == nil {
		return nil, fmt.Errorf("DoH3 requires a cancellable finalmask UDP dialer")
	}
	authority := dohAuthority(endpoint)
	dest, addr, err := resolverTarget(authority, config.Bootstrap, xnet.Network_UDP)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := resolverTLSConfig(config, endpoint.Hostname(), http3.NextProtoH3)
	if err != nil {
		return nil, err
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	pool := &doh3TransportPool{generations: make(map[*doh3TransportGeneration]struct{})}
	pool.newGeneration = func() *doh3TransportGeneration {
		state := newDoHDialState()
		transport := &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: resolverRequestTimeout,
				MaxIdleTimeout:       xnet.ConnIdleTimeout,
				MaxIncomingStreams:   -1,
			},
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 * 1024,
			Dial: func(ctx context.Context, target string, cfg *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				if !strings.EqualFold(target, authority) {
					return nil, fmt.Errorf("DoH3 dial changed HTTPS origin")
				}
				ctx, finish, err := state.dialContext(ctx)
				if err != nil {
					return nil, err
				}
				defer finish()
				conn, err := dialer.DialUDPContext(ctx, dest)
				if err != nil {
					return nil, err
				}
				wrapper, ok := conn.(*xnet.PacketConnWrapper)
				if !ok || wrapper == nil || wrapper.PacketConn == nil {
					if !ok && conn != nil {
						_ = conn.Close()
					}
					return nil, fmt.Errorf("DoH3 dialer must return a PacketConnWrapper")
				}
				remote, ok := wrapper.RemoteAddr().(*net.UDPAddr)
				_, virtual := wrapper.PacketConn.(*internet.FakePacketConn)
				zeroPeer := virtual && remote != nil && remote.IP.IsUnspecified() && remote.Port == 0
				if !ok || remote == nil || remote.IP.To16() == nil || (remote.Port <= 0 && !zeroPeer) || remote.Port > 65535 {
					_ = wrapper.Close()
					return nil, fmt.Errorf("DoH3 dialer returned an invalid UDP peer")
				}
				socket := &doh3Socket{
					packetConn: wrapper.PacketConn,
					transport:  &quic.Transport{Conn: wrapper.PacketConn},
					state:      state,
				}
				if err := state.add(socket); err != nil {
					return nil, err
				}
				secure, err := socket.transport.Dial(ctx, remote, cfg, quicConfig)
				if err != nil {
					_ = socket.Close()
					return nil, err
				}
				if secure.ConnectionState().TLS.NegotiatedProtocol != http3.NextProtoH3 {
					_ = secure.CloseWithError(0, "invalid DoH3 ALPN")
					_ = socket.Close()
					return nil, fmt.Errorf("DoH3 server did not negotiate h3")
				}
				context.AfterFunc(secure.Context(), func() { _ = socket.Close() })
				return secure, nil
			},
		}
		return &doh3TransportGeneration{transport: transport, state: state}
	}
	client := &http.Client{Transport: pool, CheckRedirect: rejectDoHRedirect}
	return newRequestResolver(addr, func(ctx context.Context, query []byte) ([]byte, error) {
		return exchangeDoH(ctx, client, endpoint.String(), query)
	}, pool.Close), nil
}

type doh3TransportPool struct {
	mu            sync.Mutex
	closed        bool
	current       *doh3TransportGeneration
	generations   map[*doh3TransportGeneration]struct{}
	newGeneration func() *doh3TransportGeneration
}

type doh3TransportGeneration struct {
	transport *http3.Transport
	state     *dohDialState
	leases    int
	retired   bool
	closeOnce sync.Once
}

func (p *doh3TransportPool) acquire() (*doh3TransportGeneration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, io.ErrClosedPipe
	}
	generation := p.current
	if generation == nil {
		generation = p.newGeneration()
		p.current = generation
		p.generations[generation] = struct{}{}
	}
	generation.leases++
	return generation, nil
}

func (p *doh3TransportPool) RoundTrip(request *http.Request) (*http.Response, error) {
	generation, err := p.acquire()
	if err != nil {
		return nil, err
	}
	response, err := generation.transport.RoundTrip(request)
	if err != nil {
		if request.Context().Err() == nil {
			p.retire(generation)
		}
		p.release(generation)
		return nil, err
	}
	if response == nil || response.Body == nil {
		p.release(generation)
		return response, nil
	}
	response.Body = &doh3LeasedBody{
		ReadCloser: response.Body,
		release:    func() { p.release(generation) },
	}
	return response, nil
}

func (p *doh3TransportPool) retire(generation *doh3TransportGeneration) {
	p.mu.Lock()
	generation.retired = true
	if p.current == generation {
		p.current = nil
	}
	closeGeneration := generation.leases == 0
	p.mu.Unlock()
	if closeGeneration {
		p.closeGeneration(generation)
	}
}

func (p *doh3TransportPool) release(generation *doh3TransportGeneration) {
	p.mu.Lock()
	generation.leases--
	closeGeneration := generation.retired && generation.leases == 0
	p.mu.Unlock()
	if closeGeneration {
		p.closeGeneration(generation)
	}
}

func (p *doh3TransportPool) closeGeneration(generation *doh3TransportGeneration) {
	generation.closeOnce.Do(func() {
		generation.state.cancel()
		_ = generation.transport.Close()
		generation.state.Close()
	})
	p.mu.Lock()
	delete(p.generations, generation)
	p.mu.Unlock()
}

func (p *doh3TransportPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.current = nil
	generations := make([]*doh3TransportGeneration, 0, len(p.generations))
	for generation := range p.generations {
		generation.retired = true
		generations = append(generations, generation)
	}
	p.mu.Unlock()
	for _, generation := range generations {
		generation.state.cancel()
	}
	for _, generation := range generations {
		p.closeGeneration(generation)
	}
}

type doh3LeasedBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
	err     error
}

func (b *doh3LeasedBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		b.release()
	})
	return b.err
}

type doh3Socket struct {
	packetConn net.PacketConn
	transport  *quic.Transport
	state      *dohDialState
	once       sync.Once
}

func (s *doh3Socket) Close() error {
	s.once.Do(func() {
		// Closing the socket also unblocks PacketConns that cannot implement read deadlines.
		_ = s.packetConn.Close()
		_ = s.transport.Close()
		s.state.remove(s)
	})
	return nil
}
