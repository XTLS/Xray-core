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

func newPingClient(ctx context.Context, dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  newHTTPClient(ctx, dispatcher, handler, timeout),
	}
}

func newDirectPingClient(destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		destination: destination,
		httpClient:  &http.Client{Timeout: timeout},
	}
}

func newHTTPClient(ctxv context.Context, dispatcher routing.Dispatcher, handler string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return tagged.Dialer(ctxv, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
func (s *pingClient) MeasureDelay(httpMethod string) (time.Duration, error) {
	d, _, err := s.measure(context.Background(), httpMethod)
	return d, err
}

// measure sends one request and returns the full request time (with
// connection setup) and the HTTP status of the response. Any response counts
// as success, as in MeasureDelay.
func (s *pingClient) measure(ctx context.Context, httpMethod string) (time.Duration, int, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}

	req, err := http.NewRequestWithContext(ctx, httpMethod, s.destination, nil)
	if err != nil {
		return rttFailed, 0, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, 0, err
	}
	if httpMethod == http.MethodGet {
		_, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			resp.Body.Close()
			return rttFailed, resp.StatusCode, err
		}
	}
	resp.Body.Close()

	return time.Since(start), resp.StatusCode, nil
}

// ProbeOnce sends one request to destination through the outbound with the
// given tag, bypassing routing, and returns the full request time and the
// HTTP status. It is used by the ProbeOutbound API: nothing is stored in
// health results. ctx must carry the Xray instance; cancelling it aborts
// the request.
func ProbeOnce(ctx context.Context, dispatcher routing.Dispatcher, tag, destination, httpMethod string, timeout time.Duration) (time.Duration, int, error) {
	c := newPingClient(ctx, dispatcher, destination, timeout, tag)
	return c.measure(ctx, httpMethod)
}
