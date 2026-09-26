package burst

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
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
func (s *pingClient) MeasureDelay(httpMethod string, expectedStatus int32, minimumResponseBytes int64) (time.Duration, error) {
	if s.httpClient == nil {
		panic("pingClient not initialized")
	}
	if expectedStatus != 0 && (expectedStatus < 100 || expectedStatus > 599) {
		return rttFailed, fmt.Errorf("expected status must be 0 or a valid HTTP status code")
	}
	if minimumResponseBytes < 0 {
		return rttFailed, fmt.Errorf("minimum response bytes must not be negative")
	}
	if minimumResponseBytes > 0 && !strings.EqualFold(httpMethod, http.MethodGet) {
		return rttFailed, fmt.Errorf("minimum response bytes requires GET, got %s", httpMethod)
	}

	req, err := http.NewRequest(httpMethod, s.destination, nil)
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

	if expectedStatus != 0 && resp.StatusCode != int(expectedStatus) {
		return rttFailed, fmt.Errorf("unexpected HTTP status: got %d, want %d", resp.StatusCode, expectedStatus)
	}
	if strings.EqualFold(httpMethod, http.MethodGet) {
		var responseBytes int64
		responseBytes, err = io.Copy(io.Discard, resp.Body)
		if err != nil {
			return rttFailed, err
		}
		if responseBytes < minimumResponseBytes {
			return rttFailed, fmt.Errorf("response body too short: got %d bytes, want at least %d", responseBytes, minimumResponseBytes)
		}
	}

	return time.Since(start), nil
}
