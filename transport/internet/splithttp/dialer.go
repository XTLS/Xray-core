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
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
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

type reusedClient struct {
	download *http.Client
	upload   *http.Client
	isH2     bool
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

var (
	globalDialerMap    map[dialerConf]reusedClient
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) reusedClient {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]reusedClient)
	}

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	isH2 := tlsConfig != nil && !(len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "http/1.1")

	var gotlsConfig *gotls.Config

	if tlsConfig != nil {
		gotlsConfig = tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	}

	dialContext := func(ctxInner context.Context) (net.Conn, error) {
		conn, err := internet.DialSystem(ctxInner, dest, streamSettings.SocketSettings)
		if err != nil {
			return nil, err
		}

		if gotlsConfig != nil {
			if fingerprint := tls.GetFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
				conn = tls.UClient(conn, gotlsConfig, fingerprint)
				if err := conn.(*tls.UConn).HandshakeContext(ctxInner); err != nil {
					return nil, err
				}
			} else {
				conn = tls.Client(conn, gotlsConfig)
			}
		}

		return conn, nil
	}

	var uploadTransport http.RoundTripper
	var downloadTransport http.RoundTripper

	if isH2 {
		downloadTransport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: 90 * time.Second,
		}
		uploadTransport = downloadTransport
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		downloadTransport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: 90 * time.Second,
			// chunked transfer download with keepalives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}

		// we use uploadRawPool for that
		uploadTransport = nil
	}

	client := reusedClient{
		download: &http.Client{
			Transport: downloadTransport,
		},
		upload: &http.Client{
			Transport: uploadTransport,
		},
		isH2:           isH2,
		uploadRawPool:  &sync.Pool{},
		dialUploadConn: dialContext,
	}

	globalDialerMap[dialerConf{dest, streamSettings}] = client
	return client
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing splithttp to ", dest)

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
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()

	var downResponse io.ReadCloser
	gotDownResponse := done.New()

	sessionIdUuid := uuid.New()
	sessionId := sessionIdUuid.String()

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
			httptrace.WithClientTrace(context.WithoutCancel(ctx), trace),
			"GET",
			requestURL.String()+sessionId,
			nil,
		)
		if err != nil {
			errors.LogInfoInner(ctx, err, "failed to construct download http request")
			gotDownResponse.Close()
			return
		}

		req.Header = transportConfiguration.GetRequestHeader()

		response, err := httpClient.download.Do(req)
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

		// skip "ooooooooook" response
		trashHeader := []byte{0}
		for {
			_, err = io.ReadFull(response.Body, trashHeader)
			if err != nil {
				response.Body.Close()
				errors.LogInfoInner(ctx, err, "failed to read initial response")
				gotDownResponse.Close()
				return
			}
			if trashHeader[0] == 'k' {
				break
			}
		}

		downResponse = response.Body
		gotDownResponse.Close()
	}()

	uploadUrl := requestURL.String() + sessionId + "/"

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
					errors.LogInfoInner(ctx, err, "failed to send upload")
					uploadPipeReader.Interrupt()
					return
				}

				req.Header = transportConfiguration.GetRequestHeader()

				if httpClient.isH2 {
					resp, err := httpClient.upload.Do(req)
					if err != nil {
						errors.LogInfoInner(ctx, err, "failed to send upload")
						uploadPipeReader.Interrupt()
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode != 200 {
						errors.LogInfo(ctx, "failed to send upload, bad status code:", resp.Status)
						uploadPipeReader.Interrupt()
						return
					}
				} else {
					var err error
					var uploadConn any
					for i := 0; i < 5; i++ {
						uploadConn = httpClient.uploadRawPool.Get()
						if uploadConn == nil {
							uploadConn, err = httpClient.dialUploadConn(context.WithoutCancel(ctx))
							if err != nil {
								errors.LogInfoInner(ctx, err, "failed to connect upload")
								uploadPipeReader.Interrupt()
								return
							}
						}

						err = req.Write(uploadConn.(net.Conn))
						if err == nil {
							break
						}
					}

					if err != nil {
						errors.LogInfoInner(ctx, err, "failed to send upload")
						uploadPipeReader.Interrupt()
						return
					}

					httpClient.uploadRawPool.Put(uploadConn)
				}
			}()

		}
	}()

	// we want to block Dial until we know the remote address of the server,
	// for logging purposes
	<-gotConn.Wait()

	// necessary in order to send larger chunks in upload
	bufferedUploadPipeWriter := buf.NewBufferedWriter(uploadPipeWriter)
	bufferedUploadPipeWriter.SetBuffered(false)

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			<-gotDownResponse.Wait()
			if downResponse == nil {
				return nil, errors.New("downResponse failed")
			}
			return downResponse, nil
		},
	}

	conn := splitConn{
		writer:     bufferedUploadPipeWriter,
		reader:     lazyDownload,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return stat.Connection(&conn), nil
}
