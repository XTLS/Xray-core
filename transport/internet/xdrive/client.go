package xdrive

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
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
// progress, see serviceTransport.RoundTrip
func newServiceClient(streamSettings *internet.MemoryStreamConfig, stall time.Duration, maxConns int) *http.Client {
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
			stall:  stall,
		},
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
