package splithttp

import (
	"context"
	"io"
	gonet "net"

	"github.com/xtls/xray-core/common/errors"
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

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (io.ReadCloser, gonet.Addr, gonet.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("bidirectional streaming for browser dialer not implemented yet")
	}

	conn, err := browser_dialer.DialGet(url, c.transportConfig.GetRequestHeader(url))
	dummyAddr := &gonet.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	bytes, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	err = browser_dialer.DialPost(url, c.transportConfig.GetRequestHeader(url), bytes)
	if err != nil {
		return err
	}

	return nil
}
