package splithttp

import (
	"bytes"
	"context"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	// (ctx, baseURL, payload) -> err
	// baseURL already contains sessionId and seq
	SendUploadRequest(context.Context, string, io.ReadWriteCloser, int64) error

	// (ctx, baseURL) -> (downloadReader, remoteAddr, localAddr)
	// baseURL already contains sessionId
	OpenDownload(context.Context, string) (io.ReadCloser, net.Addr, net.Addr, error)
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	download        *http.Client
	upload          *http.Client
	isH2            bool
	isH3            bool
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func splitHttpWriteHeaderWhenEmpty(headers *http.Header, key string, value string) {
	if headers.Get(key) == "" {
		headers.Add(key, value)
	}
}

func (c *DefaultDialerClient) OpenDownload(ctx context.Context, baseURL string) (io.ReadCloser, gonet.Addr, gonet.Addr, error) {
	var remoteAddr gonet.Addr
	var localAddr gonet.Addr
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()

	var downResponse io.ReadCloser
	gotDownResponse := done.New()

	go func() {
		trace := &httptrace.ClientTrace{
			GotConn: func(connInfo httptrace.GotConnInfo) {
				remoteAddr = connInfo.Conn.RemoteAddr()
				localAddr = connInfo.Conn.LocalAddr()
				gotConn.Close()
			},
		}

		// in case we hit an error, we want to unblock this part
		defer gotConn.Close()

		req, err := http.NewRequestWithContext(
			httptrace.WithClientTrace(ctx, trace),
			"GET",
			baseURL,
			nil,
		)
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to construct download http request")
			gotDownResponse.Close()
			return
		}

		req.Header = c.transportConfig.GetRequestHeader()
		// Tell the middleboxes to expect an SSE response
		splitHttpWriteHeaderWhenEmpty(&req.Header, "Accept", "text/event-stream")
		// Tell the middleboxes to not serve from cache altogether
		splitHttpWriteHeaderWhenEmpty(&req.Header, "Cache-Control", "no-cache")

		response, err := c.download.Do(req)
		gotConn.Close()
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to send download http request")
			gotDownResponse.Close()
			return
		}

		if response.StatusCode != 200 {
			response.Body.Close()
			errors.LogInfo(ctx, "invalid status code on download:", response.Status)
			gotDownResponse.Close()
			return
		}

		downResponse = response.Body
		gotDownResponse.Close()
	}()

	if c.isH3 {
		gotConn.Close()
	}

	// we want to block Dial until we know the remote address of the server,
	// for logging purposes
	<-gotConn.Wait()

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			<-gotDownResponse.Wait()
			if downResponse == nil {
				return nil, errors.New("downResponse failed")
			}
			return downResponse, nil
		},
	}

	return lazyDownload, remoteAddr, localAddr, nil
}

func (c *DefaultDialerClient) SendUploadRequest(ctx context.Context, url string, payload io.ReadWriteCloser, contentLength int64) error {
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.ContentLength = contentLength
	req.Header = c.transportConfig.GetRequestHeader()

	if c.isH2 || c.isH3 {
		resp, err := c.upload.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBytes := new(bytes.Buffer)
		common.Must(req.Write(requestBytes))

		var uploadConn any

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				uploadConn, err = c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
			}

			_, err = uploadConn.(net.Conn).Write(requestBytes.Bytes())

			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else if newConnection {
				return err
			}
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}
