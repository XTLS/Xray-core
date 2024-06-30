package splithttp

import (
	"context"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	// (ctx, baseURL, payload) -> err
	// baseURL already contains sessionId and seq
	SendUploadRequest(context.Context, string, io.ReadWriteCloser) error

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
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
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

func (c *DefaultDialerClient) SendUploadRequest(ctx context.Context, url string, payload io.ReadWriteCloser) error {
	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return err
	}
	req.Header = c.transportConfig.GetRequestHeader()

	if c.isH2 {
		resp, err := c.upload.Do(req)
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		var err error
		var uploadConn any
		for i := 0; i < 5; i++ {
			uploadConn = c.uploadRawPool.Get()
			if uploadConn == nil {
				uploadConn, err = c.dialUploadConn(ctx)
				if err != nil {
					return err
				}
			}

			err = req.Write(uploadConn.(net.Conn))
			if err == nil {
				break
			}
		}

		if err != nil {
			return err
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}
