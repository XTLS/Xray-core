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
	ctx         context.Context
	destination string
	dispatcher  routing.Dispatcher
	handler     string
	timeout     time.Duration
	direct      bool
}

func newPingClient(ctx context.Context, dispatcher routing.Dispatcher, destination string, timeout time.Duration, handler string) *pingClient {
	return &pingClient{
		ctx:         ctx,
		destination: destination,
		dispatcher:  dispatcher,
		handler:     handler,
		timeout:     timeout,
	}
}

func newDirectPingClient(destination string, timeout time.Duration) *pingClient {
	return &pingClient{
		ctx:         context.Background(),
		destination: destination,
		timeout:     timeout,
		direct:      true,
	}
}

func newHTTPClient(ctx context.Context, dispatcher routing.Dispatcher, handler string) *http.Client {
	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			dest, err := net.ParseDestination(network + ":" + addr)
			if err != nil {
				return nil, err
			}
			return tagged.Dialer(ctx, dispatcher, dest, handler)
		},
	}
	return &http.Client{
		Transport: tr,
		// don't follow redirect
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// MeasureDelay returns the delay time of the request to dest
func (s *pingClient) MeasureDelay(httpMethod string) (time.Duration, error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return s.MeasureDelayContext(ctx, httpMethod)
}

// MeasureDelayContext returns the delay time of the request to dest and
// cancels the request when ctx is done.
func (s *pingClient) MeasureDelayContext(ctx context.Context, httpMethod string) (time.Duration, error) {
	if ctx == nil {
		panic("pingClient context is nil")
	}
	var requestCtx context.Context
	var cancel context.CancelFunc
	if s.timeout > 0 {
		requestCtx, cancel = context.WithTimeout(ctx, s.timeout)
	} else {
		requestCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	var httpClient *http.Client
	if s.direct {
		httpClient = &http.Client{}
	} else {
		// net/http deliberately detaches the context passed to DialContext so a
		// connection attempt may be reused by another request. Burst probes use
		// one transport per request instead, allowing the captured Xray context
		// to retain its instance value and end with this exact probe deadline.
		httpClient = newHTTPClient(requestCtx, s.dispatcher, s.handler)
	}

	req, err := http.NewRequestWithContext(requestCtx, httpMethod, s.destination, nil)
	if err != nil {
		return rttFailed, err
	}
	utils.TryDefaultHeadersWith(req.Header, "nav")

	start := time.Now()
	resp, err := httpClient.Do(req)
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
