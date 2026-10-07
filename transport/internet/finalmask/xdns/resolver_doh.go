package xdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type dohTransport struct {
	url       string
	client    *http.Client
	transport *http.Transport
}

func NewDOHResolver(config *ResolverProto, dialer *finalmask.Dialer) (Resolver, error) {
	config, err := normalizeResolver(config)
	if err != nil {
		return nil, err
	}
	if config.Type != "doh" || dialer == nil || (dialer.DialTCP == nil && dialer.DialTCPContext == nil) {
		return nil, errors.New("invalid DoH resolver or TCP dialer")
	}
	u, err := url.Parse(config.Addr)
	if err != nil {
		return nil, err
	}
	dest, err := xnet.ParseDestination("tcp:" + u.Host)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialResolverTCP(ctx, dialer, dest)
		},
		TLSClientConfig:       &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   resolverTimeout,
		ResponseHeaderTimeout: resolverTimeout,
		ForceAttemptHTTP2:     true,
		MaxConnsPerHost:       resolverMaxConcurrent,
		MaxIdleConnsPerHost:   resolverMaxConcurrent,
		IdleConnTimeout:       time.Minute,
	}
	r := &dohTransport{url: config.Addr, transport: transport}
	r.client = &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("DoH redirects are not allowed")
		},
	}
	return newEncryptedResolver(r, dest), nil
}

func (r *dohTransport) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) < 12 || len(query) > resolverMaxResponse {
		return nil, errors.New("invalid DoH query length")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(query))
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
		return nil, errors.New("DoH server returned non-200 status")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		return nil, errors.New("DoH server returned invalid content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, resolverMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) < 12 || len(body) > resolverMaxResponse || !matchesDNSQuestion(query, body) || !bytes.Equal(query[:2], body[:2]) {
		return nil, errors.New("invalid DoH DNS response")
	}
	return body, nil
}

func (r *dohTransport) Close() { r.transport.CloseIdleConnections() }
