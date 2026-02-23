package splithttp

import (
	"context"
	"io"
	"net/http"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/websocket"
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

	request.Header = c.transportConfig.GetRequestHeader()
	length := int(c.transportConfig.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.transportConfig.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.transportConfig.XPaddingPlacement,
			Key:       c.transportConfig.XPaddingKey,
			Header:    c.transportConfig.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.transportConfig.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}

	c.transportConfig.ApplyXPaddingToRequest(request, config)
	c.transportConfig.ApplyMetaToRequest(request, sessionId, "")

	conn, err := browser_dialer.DialGet(request.URL.String(), request.Header, request.Cookies())
	dummyAddr := &net.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, body io.Reader, contentLength int64) error {
	bytes, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	request, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}

	dataPlacement := c.transportConfig.GetNormalizedUplinkDataPlacement()

	if dataPlacement == PlacementBody || dataPlacement == PlacementAuto {
		request.Header = c.transportConfig.GetRequestHeader()
	} else {
		switch dataPlacement {
		case PlacementHeader:
			request.Header = c.transportConfig.GetRequestHeaderWithPayload(bytes)
		case PlacementCookie:
			request.Header = c.transportConfig.GetRequestHeader()
			for _, cookie := range c.transportConfig.GetRequestCookiesWithPayload(bytes) {
				request.AddCookie(cookie)
			}
		}
		bytes = nil
	}


	length := int(c.transportConfig.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.transportConfig.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.transportConfig.XPaddingPlacement,
			Key:       c.transportConfig.XPaddingKey,
			Header:    c.transportConfig.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.transportConfig.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}

	c.transportConfig.ApplyXPaddingToRequest(request, config)
	c.transportConfig.ApplyMetaToRequest(request, sessionId, seqStr)

	err = browser_dialer.DialPacket(method, request.URL.String(), request.Header, request.Cookies(), bytes)
	if err != nil {
		return err
	}

	return nil
}
