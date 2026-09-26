package splithttp

import (
	"context"
	"io"
	"net/http"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
)

// BrowserDialerClient implements splithttp.DialerClient in terms of browser dialer
type BrowserDialerClient struct {
	transportConfig *Config
}

func (c *BrowserDialerClient) IsClosed() bool {
	panic("not implemented yet")
}

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("bidirectional streaming for browser dialer not implemented yet")
	}

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	c.transportConfig.FillStreamRequest(request, sessionId, "")

	return browser_dialer.DialGetStream(request.URL.String(), request.Header, request.Cookies())
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}

	err = c.transportConfig.FillPacketRequest(request, sessionId, seqStr, payload)
	if err != nil {
		return err
	}

	var bytes []byte
	if request.Body != nil {
		bytes, err = io.ReadAll(request.Body)
		if err != nil {
			return err
		}
	}

	err = browser_dialer.DialPacket(method, request.URL.String(), request.Header, request.Cookies(), bytes)
	if err != nil {
		return err
	}

	return nil
}
