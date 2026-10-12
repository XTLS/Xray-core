package xdns

import (
	"context"
	"crypto/tls"
	"fmt"
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
	client := &http.Client{Transport: transport, CheckRedirect: rejectDoHRedirect}
	return newRequestResolver(addr, func(ctx context.Context, query []byte) ([]byte, error) {
		return exchangeDoH(ctx, client, endpoint.String(), query)
	}, func() {
		state.cancel()
		_ = transport.Close()
		state.Close()
	}), nil
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
