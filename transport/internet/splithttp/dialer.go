package splithttp

import (
	"context"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/semaphore"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]*http.Client
	globalDialerAccess sync.Mutex
)

func destroyHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*http.Client)
	}

	delete(globalDialerMap, dialerConf{dest, streamSettings})

}

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) *http.Client {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*http.Client)
	}

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)

	var gotlsConfig *gotls.Config

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	}

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}

		if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := conn.(*tls.UConn).HandshakeContext(ctx); err != nil {
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
			}
		}

		return conn, nil
	}

	var httpTransport http.RoundTripper

	if tlsConfig != nil {
		httpTransport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: 90 * time.Second,
		}
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}
		httpTransport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: 90 * time.Second,
			MaxIdleConns:    100,
		}
	}

	client := &http.Client{
		Transport: httpTransport,
	}

	globalDialerMap[dialerConf{dest, streamSettings}] = client
	return client
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	newError("dialing splithttp to ", dest).WriteToLog(session.ExportIDToError(ctx))

	var requestURL url.URL

	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)

	maxConcurrentUploads := transportConfiguration.GetNormalizedMaxConcurrentUploads()
	maxUploadSize := transportConfiguration.GetNormalizedMaxUploadSize()

	if tlsConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" {
		requestURL.Host = dest.NetAddr()
	}
	requestURL.Path = transportConfiguration.GetNormalizedPath()

	httpClient := getHTTPClient(ctx, dest, streamSettings)

	var remoteAddr gonet.Addr
	var localAddr gonet.Addr

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
		},
	}

	sessionIdUuid := uuid.New()
	sessionId := sessionIdUuid.String()

	req, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, trace),
		"GET",
		requestURL.String()+"?session="+sessionId,
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header = transportConfiguration.GetRequestHeader()

	downResponse, err := httpClient.Do(req)
	if err != nil {
		// workaround for various connection pool related issues. if the http client
		// ever fails to send a request, we simply delete it entirely.
		destroyHTTPClient(ctx, dest, streamSettings)
		return nil, newError("failed to send download http request, destroying client").Base(err)
	}

	if downResponse.StatusCode != 200 {
		io.Copy(io.Discard, downResponse.Body)
		downResponse.Body.Close()
		return nil, newError("invalid status code on download:", downResponse.Status)
	}

	uploadUrl := requestURL.String() + "?session=" + sessionId + "&seq="

	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize))

	go func() {
		requestsLimiter := semaphore.New(int(maxConcurrentUploads))
		var requestCounter int64

		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		for {
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			<-requestsLimiter.Wait()

			url := uploadUrl + strconv.FormatInt(requestCounter, 10)
			requestCounter += 1

			go func() {
				defer requestsLimiter.Signal()
				req, err := http.NewRequest("POST", url, &buf.MultiBufferContainer{MultiBuffer: chunk})
				if err != nil {
					newError("failed to send upload").Base(err).WriteToLog()
					return
				}

				req.Header = transportConfiguration.GetRequestHeader()

				resp, err := httpClient.Do(req)
				if err != nil {
					newError("failed to send upload").Base(err).WriteToLog()
					return
				}

				defer resp.Body.Close()
				defer io.Copy(io.Discard, resp.Body)

				if resp.StatusCode != 200 {
					newError("failed to send upload, bad status code:", resp.Status).WriteToLog()
					return
				}

			}()

		}
	}()

	// skip "ok" response
	trashHeader := []byte{0, 0}
	_, err = io.ReadFull(downResponse.Body, trashHeader)
	if err != nil {
		io.Copy(io.Discard, downResponse.Body)
		downResponse.Body.Close()
		return nil, newError("failed to read initial response")
	}

	conn := splitConn{
		writer: &uploadWriter{
			uploadPipe: buf.NewBufferedWriter(uploadPipeWriter),
		},
		reader:     &drainBeforeClose{reader: downResponse.Body},
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return stat.Connection(&conn), nil
}

type uploadWriter struct {
	uploadPipe *buf.BufferedWriter
}

func (c *uploadWriter) Write(b []byte) (int, error) {
	bytes, err := c.uploadPipe.Write(b)
	if err == nil {
		c.uploadPipe.Flush()
	}
	return bytes, err
}

func (c *uploadWriter) Close() error {
	return c.uploadPipe.Close()
}

// a wrapper around http responses for draining them before closing. apparently
// there are various issues around connection reuse _specifically on HTTP/1.1_
// if this isn't done. if the connection fails to be reused, we use
// destroyHTTPClient as a last resort to not brick the transport entirely.
type drainBeforeClose struct {
	reader io.ReadCloser
}

func (c *drainBeforeClose) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *drainBeforeClose) Close() error {
	io.Copy(io.Discard, c.reader)
	return c.reader.Close()
}
