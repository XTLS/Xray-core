package xdrive

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type serviceTransport struct {
	plain  http.RoundTripper
	secure http.RoundTripper
}

func (t *serviceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme == "https" {
		return t.secure.RoundTrip(r)
	}
	return t.plain.RoundTrip(r)
}

func newServiceClient(streamSettings *internet.MemoryStreamConfig, timeout time.Duration, maxConns int) *http.Client {
	var (
		tlsConfig     *tls.Config
		realityConfig *reality.Config
		sockopt       *internet.SocketConfig
		fronting      *net.Destination
	)
	if streamSettings != nil {
		tlsConfig = tls.ConfigFromStreamSettings(streamSettings)
		realityConfig = reality.ConfigFromStreamSettings(streamSettings)
		sockopt = streamSettings.SocketSettings
		fronting = streamSettings.Destination
	}
	overHTTP2 := allowsHTTP2(tlsConfig, realityConfig)

	dial := func(ctx context.Context, addr string) (net.Conn, net.Destination, error) {
		host, err := net.ParseDestination("tcp:" + addr)
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
		if streamSettings.FinalMask != nil {
			conn, err = streamSettings.FinalMask.DialTCP(ctx, target)
		} else {
			conn, err = internet.DialSystem(ctx, target, sockopt)
		}
		if err != nil {
			return nil, host, errors.New("failed to dial to dest").Base(err)
		}
		return conn, host, nil
	}

	dialPlain := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, _, err := dial(ctx, addr)
		return conn, err
	}

	dialTLS := func(ctx context.Context, addr string) (net.Conn, error) {
		conn, host, err := dial(ctx, addr)
		if err != nil {
			return nil, err
		}

		if realityConfig != nil {
			return reality.UClient(conn, realityConfig, ctx, host)
		}

		gotlsConfig := &gotls.Config{ServerName: host.Address.String()}
		if tlsConfig != nil {
			gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(host))
		}
		if len(gotlsConfig.NextProtos) != 1 {
			if overHTTP2 {
				gotlsConfig.NextProtos = []string{"h2"}
			} else {
				gotlsConfig.NextProtos = []string{"http/1.1"}
			}
		}

		if tlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				uconn := tls.UClient(conn, gotlsConfig, fingerprint)
				if err := uconn.(*tls.UConn).HandshakeContext(ctx); err != nil {
					conn.Close()
					return nil, err
				}
				return uconn, nil
			}
		}
		return tls.Client(conn, gotlsConfig), nil
	}

	var secure http.RoundTripper
	if overHTTP2 {
		secure = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialTLS(ctx, addr)
			},
			IdleConnTimeout: net.ConnIdleTimeout,
		}
	} else {
		secure = &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTLS(ctx, addr)
			},
			IdleConnTimeout:     net.ConnIdleTimeout,
			MaxIdleConns:        maxConns,
			MaxIdleConnsPerHost: maxConns,
			MaxConnsPerHost:     maxConns,
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
			secure: secure,
		},
		Timeout: timeout,
	}
}

func allowsHTTP2(tlsConfig *tls.Config, realityConfig *reality.Config) bool {
	if realityConfig != nil {
		return true
	}
	if tlsConfig == nil {
		return false
	}
	return len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "h2"
}
