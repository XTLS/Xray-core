package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	goerrors "errors"
	"io"
	"mime"
	stdnet "net"
	"net/http"
	"sync"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"golang.org/x/net/http2"
)

type dohResolver struct {
	spec   resolverSpec
	dialer *finalmask.Dialer
	client *http.Client
	sem    chan struct{}
	close  sync.Once
}

func newDOHResolver(spec resolverSpec, dialer *finalmask.Dialer) *dohResolver {
	r := &dohResolver{spec: spec, dialer: dialer, sem: make(chan struct{}, resolverMaxConcurrent)}
	transport := &http2.Transport{
		DialTLSContext: r.dialTLS,
	}
	r.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return goerrors.New("doh redirects are not allowed")
		},
	}
	return r
}

func (r *dohResolver) dialTLS(ctx context.Context, _, _ string, _ *tls.Config) (stdnet.Conn, error) {
	host, portString, err := stdnet.SplitHostPort(r.spec.server)
	if err != nil {
		return nil, err
	}
	port, err := xnet.PortFromString(portString)
	if err != nil {
		return nil, err
	}
	raw, err := dialResolverTCP(ctx, r.dialer, xnet.TCPDestination(xnet.ParseAddress(host), port))
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func (r *dohResolver) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.spec.dohURL.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil, goerrors.New("doh server returned non-200 status")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		return nil, goerrors.New("doh server returned invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(body) > 65535 {
		return nil, goerrors.New("doh response too large")
	}
	return body, nil
}

func (r *dohResolver) Close() error {
	r.close.Do(func() {
		r.client.CloseIdleConnections()
	})
	return nil
}
