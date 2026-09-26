package burst

import (
	"context"
	"io"
	"net/http"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/tagged"
)

type pingClient struct {
	destination string
	httpClient  *http.Client
}

type requestContextKey struct{}

type requestContextTransport struct {
	transport *http.Transport
}

func (t *requestContextTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// The standard transport may detach dial cancellation so that a connection
	// can be reused by another request. Preserve the exact request context for
	// the tagged dial, which is dedicated to this health check.
	ctx := context.WithValue(req.Context(), requestContextKey{}, req.Context())
	return t.transport.RoundTrip(req.WithContext(ctx))
}

func newPingClient(dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  newHTTPClient(dispatcher, handler, timeout),
	}
}

func newDirectPingClient(destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  &http.Client{Timeout: timeout},
	}
}

func newHTTPClient(dispatcher routing.Dispatcher, handler string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			requestCtx, ok := ctx.Value(requestContextKey{}).(context.Context)
			if !ok {
				requestCtx = ctx
			}
			return tagged.Dialer(requestCtx, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: &requestContextTransport{transport: tr},
		Timeout:   timeout,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
func (s *pingClient) MeasureDelay(ctx context.Context, httpMethod string) (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}

	req, err := http.NewRequestWithContext(ctx, httpMethod, s.destination, nil)
	if err != nil {
		return rttFailed, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, err
	}
	defer resp.Body.Close()
	if httpMethod == http.MethodGet {
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return rttFailed, err
		}
	}

	return time.Since(start), nil
}
