package splithttp

import (
	"bytes"
	"context"
	stderrors "errors"
	"fmt"
	"io"
	stdnet "net"
	"net/http"
	"net/http/httptrace"
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

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          atomic.Bool
	httpVersion     string
	access          sync.Mutex
	lifetime        context.Context
	cancel          context.CancelFunc
	connections     map[*clientConn]struct{}
	uploadRawPool   []*H1Conn
	closeOnce       sync.Once
	closeErr        error
	dialUploadConn  func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *DefaultDialerClient) lifetimeContext() context.Context {
	c.access.Lock()
	defer c.access.Unlock()
	if c.lifetime == nil {
		c.lifetime, c.cancel = context.WithCancel(context.Background())
		if c.closed.Load() {
			c.cancel()
		}
	}
	return c.lifetime
}

// Keep the existing request lifetime independent of the caller, but allow the
// owning outbound to terminate it when its transport configuration is closed.
func (c *DefaultDialerClient) requestContext(ctx context.Context) (context.Context, func(), error) {
	if c.closed.Load() {
		return nil, nil, stdnet.ErrClosed
	}
	requestCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(c.lifetimeContext(), cancel)
	return requestCtx, func() { stop(); cancel() }, nil
}

type clientConn struct {
	net.Conn
	owner     *DefaultDialerClient
	closeOnce sync.Once
	closeErr  error
}

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.owner.access.Lock()
		delete(c.owner.connections, c)
		c.owner.access.Unlock()
	})
	return c.closeErr
}

// A connection that finishes dialing during Close must never enter a pool.
func (c *DefaultDialerClient) ownConnection(conn net.Conn) (net.Conn, error) {
	if owned, ok := conn.(*clientConn); ok && owned.owner == c {
		if c.closed.Load() {
			owned.Close()
			return nil, stdnet.ErrClosed
		}
		return owned, nil
	}
	c.access.Lock()
	if c.closed.Load() {
		c.access.Unlock()
		conn.Close()
		return nil, stdnet.ErrClosed
	}
	owned := &clientConn{Conn: conn, owner: c}
	if c.connections == nil {
		c.connections = make(map[*clientConn]struct{})
	}
	c.connections[owned] = struct{}{}
	c.access.Unlock()
	return owned, nil
}

func (c *DefaultDialerClient) takeUploadConnection(ctx context.Context) (*H1Conn, bool, error) {
	c.access.Lock()
	if c.closed.Load() {
		c.access.Unlock()
		return nil, false, stdnet.ErrClosed
	}
	if n := len(c.uploadRawPool); n > 0 {
		conn := c.uploadRawPool[n-1]
		c.uploadRawPool[n-1] = nil
		c.uploadRawPool = c.uploadRawPool[:n-1]
		c.access.Unlock()
		return conn, false, nil
	}
	c.access.Unlock()
	conn, err := c.dialUploadConn(ctx)
	if err != nil {
		return nil, true, err
	}
	// dialUploadConn uses the same owned TCP dialer as the HTTP transport;
	// preserve any TLS or REALITY wrapper around that registered connection.
	return NewH1Conn(conn), true, nil
}

func (c *DefaultDialerClient) returnUploadConnection(conn *H1Conn) {
	c.access.Lock()
	if !c.closed.Load() {
		c.uploadRawPool = append(c.uploadRawPool, conn)
		c.access.Unlock()
		return
	}
	c.access.Unlock()
	conn.Close()
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	ctx, cancel, err := c.requestContext(ctx)
	if err != nil {
		common.Close(body)
		return nil, nil, nil, err
	}
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
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		cancel()
		common.Close(body)
		errors.LogInfoInner(ctx, err, "failed to create HTTP request for "+url)
		return nil, nil, nil, err
	}
	c.transportConfig.FillStreamRequest(req, sessionId, "")

	wrc = &WaitReadCloser{wait: done.New(), onClose: cancel}
	go func() {
		resp, err := c.client.Do(req)
		gotConn.Close()
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
		if resp.StatusCode != 200 && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
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

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	ctx, cancel, err := c.requestContext(ctx)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}
	defer cancel()
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		buf.ReleaseMulti(payload)
		return err
	}
	if err := c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload); err != nil {
		return err
	}
	defer common.Close(req.Body)

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

		var h1UploadConn *H1Conn

		for {
			var newConnection bool
			h1UploadConn, newConnection, err = c.takeUploadConnection(ctx)
			if err != nil {
				return err
			}
			_, err := h1UploadConn.Write(requestBuff.Bytes())
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else {
				h1UploadConn.Close()
				if newConnection {
					return err
				}
			}
		}

		// The upload lease must cover the response as well as the write, so
		// normal XMUX retirement cannot abort a POST still being processed.
		resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
		if err != nil {
			h1UploadConn.Close()
			c.closed.Store(true)
			return fmt.Errorf("error while reading response: %w", err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			h1UploadConn.Close()
			if readErr != nil {
				return readErr
			}
			return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
		}
		if resp.Close {
			h1UploadConn.Close()
			return nil
		}
		c.returnUploadConnection(h1UploadConn)
	}

	return nil
}

func (c *DefaultDialerClient) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.access.Lock()
		cancel := c.cancel
		connections := make([]*clientConn, 0, len(c.connections))
		for conn := range c.connections {
			connections = append(connections, conn)
		}
		c.uploadRawPool = nil
		c.access.Unlock()
		if cancel != nil {
			cancel()
		}
		for _, conn := range connections {
			c.closeErr = stderrors.Join(c.closeErr, conn.Close())
		}
		c.client.CloseIdleConnections()
		if transport, ok := c.client.Transport.(*http3.Transport); ok {
			c.closeErr = stderrors.Join(c.closeErr, transport.Close())
		}
	})
	return c.closeErr
}

type WaitReadCloser struct {
	wait      *done.Instance
	reader    atomic.Pointer[io.ReadCloser]
	onClose   func()
	closeOnce sync.Once
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
	w.closeOnce.Do(func() {
		if w.onClose != nil {
			w.onClose()
		}
	})
	w.wait.Close()
	if p := w.reader.Swap(nil); p != nil {
		return (*p).Close()
	}
	return nil
}
