package splithttp

import (
	"context"
	"io"
	gonet "net"

	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// implements splithttp.DialerClient in terms of browser dialer
// has no fields because everything is global state :O)
type BrowserDialerClient struct{}

func (c *BrowserDialerClient) IsClosed() bool {
	panic("not implemented yet")
}

func (c *BrowserDialerClient) Open(ctx context.Context, pureURL string) (io.WriteCloser, io.ReadCloser) {
	panic("not implemented yet")
}

func (c *BrowserDialerClient) OpenUpload(ctx context.Context, baseURL string) io.WriteCloser {
	panic("not implemented yet")
}

func (c *BrowserDialerClient) OpenDownload(ctx context.Context, baseURL string) (io.ReadCloser, gonet.Addr, gonet.Addr, error) {
	conn, err := browser_dialer.DialGet(baseURL)
	dummyAddr := &gonet.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserDialerClient) SendUploadRequest(ctx context.Context, url string, payload io.ReadWriteCloser, contentLength int64) error {
	bytes, err := io.ReadAll(payload)
	if err != nil {
		return err
	}

	err = browser_dialer.DialPost(url, bytes)
	if err != nil {
		return err
	}

	return nil
}
