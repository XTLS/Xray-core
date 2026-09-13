package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, downlinkAck, body
	PostPacket(context.Context, string, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

// downlinkResumer is not implemented by BrowserDialerClient.
type downlinkResumer interface {
	OpenDownlink(ctx context.Context, url string, sessionId string, resumeOffset uint64) (io.ReadCloser, net.Addr, net.Addr, error)
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	return c.openStream(ctx, url, sessionId, body, uploadOnly, "")
}

func (c *DefaultDialerClient) OpenDownlink(ctx context.Context, url string, sessionId string, resumeOffset uint64) (io.ReadCloser, net.Addr, net.Addr, error) {
	return c.openStream(ctx, url, sessionId, nil, false, strconv.FormatUint(resumeOffset, 10))
}

func (c *DefaultDialerClient) openStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool, resumeValue string) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConn.Close()
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	if err != nil {
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")
	c.transportConfig.ApplyDownlinkResumeToRequest(req, resumeValue)

	wrc = &WaitReadCloser{wait: done.New()}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed.Store(true)
				errors.LogInfoInner(ctx, err, "failed to "+method+" "+url)
			}
			gotConn.Close()
			common.Close(body)
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 && resp.StatusCode != http.StatusNoContent && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusNoContent {
			wrc.(*WaitReadCloser).finished.Store(true)
		} else if resp.StatusCode != 200 {
			wrc.(*WaitReadCloser).rejected.Store(true)
		} else if v := resp.Header.Get(c.transportConfig.GetNormalizedDownlinkResumeKey()); v != "" {
			// The offset comes back as the server read it, so a middlebox that
			// drops it on the way is caught here rather than by a stream that
			// resumes in the wrong place.
			if v == resumeValue {
				wrc.(*WaitReadCloser).supported.Store(true)
			} else {
				errors.LogWarning(ctx, "XHTTP: the path changed the downlink offset from ", resumeValue, " to ", v)
			}
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			common.Close(body)
			wrc.Close()
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()

	<-gotConn.Wait()
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, downlinkAck string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, nil)
	if err != nil {
		return err
	}
	c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload)
	c.transportConfig.ApplyDownlinkResumeToRequest(req, downlinkAck)

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed.Store(true)
			return err
		}

		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		requestBuff.Grow(512 + int(req.ContentLength))
		common.Must(req.Write(requestBuff))

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						c.closed.Store(true)
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			_, err := h1UploadConn.Write(requestBuff.Bytes())
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

// HTTP/1.1 and HTTP/2 will close itself, we only handle HTTP/3 here
func (c *DefaultDialerClient) Close() error {
	transport := c.client.Transport
	if h3Transport, ok := transport.(*http3.Transport); ok {
		h3Transport.Close()
	}
	return nil
}

type WaitReadCloser struct {
	wait      *done.Instance
	reader    atomic.Pointer[io.ReadCloser]
	rejected  atomic.Bool
	supported atomic.Bool
	finished  atomic.Bool
}

// Finished reports that the server has nothing left to send, which ends the
// connection the way a complete stream-down response would.
func (w *WaitReadCloser) Finished() bool {
	return w.finished.Load()
}

// Supported reports that the server echoed the offset it resumed from, which
// is how it acknowledges the feature and proves the offset survived the path.
func (w *WaitReadCloser) Supported() bool {
	return w.supported.Load()
}

// Rejected reports that the server answered the stream-down request with a
// status other than 200, which for a resume means the offset can never be
// served again.
func (w *WaitReadCloser) Rejected() bool {
	return w.rejected.Load()
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.reader.Store(&rc)
	if w.wait.Done() {
		if p := w.reader.Swap(nil); p != nil {
			(*p).Close()
		}
	}
	w.wait.Close()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	rc := w.reader.Load()
	if rc == nil {
		<-w.wait.Wait()
		if rc = w.reader.Load(); rc == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return (*rc).Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.wait.Close()
	if p := w.reader.Swap(nil); p != nil {
		return (*p).Close()
	}
	return nil
}
