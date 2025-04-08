package burst

import (
	"context"
	"net/http"
	"time"

	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/features/routing"
	"github.com/hosemorinho412/xray-core/transport/internet/tagged"
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
func (s *pingClient) MeasureDelay() (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}
	req, err := http.NewRequest(http.MethodHead, s.destination, nil)
	if err != nil {
		return rttFailed, err
	}
	start := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return rttFailed, err
	}
	// don't wait for body
	resp.Body.Close()
	return time.Since(start), nil
}
