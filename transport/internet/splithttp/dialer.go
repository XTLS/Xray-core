package splithttp

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/semaphore"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

// defines the maximum time an idle TCP session can survive in the tunnel, so
// it should be consistent across HTTP versions and with other transports.
const connIdleTimeout = 300 * time.Second

// consistent with quic-go
const h3KeepalivePeriod = 10 * time.Second

// consistent with chrome
const h2KeepalivePeriod = 45 * time.Second

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]DialerClient
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) DialerClient {
	if browser_dialer.HasBrowserDialer() {
		return &BrowserDialerClient{}
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	isH2 := tlsConfig != nil && !(len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "http/1.1")
	isH3 := tlsConfig != nil && (len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "h3")

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]DialerClient)
	}

	if isH3 {
		dest.Network = net.Network_UDP
	}
	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client
	}

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
			if fingerprint := tls.GetRandomFingerprint(tlsConfig.Fingerprint); fingerprint != nil {
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

	var downloadTransport http.RoundTripper
	var uploadTransport http.RoundTripper

	if isH3 {
		quicConfig := &quic.Config{
			MaxIdleTimeout: connIdleTimeout,

			// these two are defaults of quic-go/http3. the default of quic-go (no
			// http3) is different, so it is hardcoded here for clarity.
			// https://github.com/quic-go/quic-go/blob/b8ea5c798155950fb5bbfdd06cad1939c9355878/http3/client.go#L36-L39
			MaxIncomingStreams: -1,
			KeepAlivePeriod:    h3KeepalivePeriod,
		}
		roundTripper := &http3.RoundTripper{
			QUICConfig:      quicConfig,
			TLSClientConfig: gotlsConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				if err != nil {
					return nil, err
				}

				var udpConn net.PacketConn
				var udpAddr *net.UDPAddr

				switch c := conn.(type) {
				case *internet.PacketConnWrapper:
					var ok bool
					udpConn, ok = c.Conn.(*net.UDPConn)
					if !ok {
						return nil, errors.New("PacketConnWrapper does not contain a UDP connection")
					}
					udpAddr, err = net.ResolveUDPAddr("udp", c.Dest.String())
					if err != nil {
						return nil, err
					}
				case *net.UDPConn:
					udpConn = c
					udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
					if err != nil {
						return nil, err
					}
				default:
					udpConn = &internet.FakePacketConn{c}
					udpAddr, err = net.ResolveUDPAddr("udp", c.RemoteAddr().String())
					if err != nil {
						return nil, err
					}
				}

				return quic.DialEarly(ctx, udpConn, udpAddr, tlsCfg, cfg)
			},
		}
		downloadTransport = roundTripper
		uploadTransport = roundTripper
	} else if isH2 {
		downloadTransport = &http2.Transport{
			DialTLSContext: func(ctxInner context.Context, network string, addr string, cfg *gotls.Config) (net.Conn, error) {
				return dialContext(ctxInner)
			},
			IdleConnTimeout: connIdleTimeout,
			ReadIdleTimeout: h2KeepalivePeriod,
		}
		uploadTransport = downloadTransport
	} else {
		httpDialContext := func(ctxInner context.Context, network string, addr string) (net.Conn, error) {
			return dialContext(ctxInner)
		}

		downloadTransport = &http.Transport{
			DialTLSContext:  httpDialContext,
			DialContext:     httpDialContext,
			IdleConnTimeout: connIdleTimeout,
			// chunked transfer download with keepalives is buggy with
			// http.Client and our custom dial context.
			DisableKeepAlives: true,
		}
		// we use uploadRawPool for that
		uploadTransport = nil
	}

	client := &DefaultDialerClient{
		transportConfig: streamSettings.ProtocolSettings.(*Config),
		download: &http.Client{
			Transport: downloadTransport,
		},
		upload: &http.Client{
			Transport: uploadTransport,
		},
		isH2:           isH2,
		isH3:           isH3,
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

	scMaxConcurrentPosts := transportConfiguration.GetNormalizedScMaxConcurrentPosts()
	scMaxEachPostBytes := transportConfiguration.GetNormalizedScMaxEachPostBytes()
	scMinPostsIntervalMs := transportConfiguration.GetNormalizedScMinPostsIntervalMs()

	if tlsConfig != nil {
		requestURL.Scheme = "https"
	} else {
		requestURL.Scheme = "http"
	}
	requestURL.Host = transportConfiguration.Host
	if requestURL.Host == "" {
		requestURL.Host = dest.NetAddr()
	}

	sessionIdUuid := uuid.New()
	requestURL.Path = transportConfiguration.GetNormalizedPath() + sessionIdUuid.String()
	requestURL.RawQuery = transportConfiguration.GetNormalizedQuery()

	httpClient := getHTTPClient(ctx, dest, streamSettings)

	maxUploadSize := scMaxEachPostBytes.roll()
	// WithSizeLimit(0) will still allow single bytes to pass, and a lot of
	// code relies on this behavior. Subtract 1 so that together with
	// uploadWriter wrapper, exact size limits can be enforced
	uploadPipeReader, uploadPipeWriter := pipe.New(pipe.WithSizeLimit(maxUploadSize - 1))

	go func() {
		requestsLimiter := semaphore.New(int(scMaxConcurrentPosts.roll()))
		var requestCounter int64

		lastWrite := time.Now()

		// by offloading the uploads into a buffered pipe, multiple conn.Write
		// calls get automatically batched together into larger POST requests.
		// without batching, bandwidth is extremely limited.
		for {
			chunk, err := uploadPipeReader.ReadMultiBuffer()
			if err != nil {
				break
			}

			<-requestsLimiter.Wait()

			seq := requestCounter
			requestCounter += 1

			go func() {
				defer requestsLimiter.Signal()

				// this intentionally makes a shallow-copy of the struct so we
				// can reassign Path (potentially concurrently)
				url := requestURL
				url.Path += "/" + strconv.FormatInt(seq, 10)
				// reassign query to get different padding
				url.RawQuery = transportConfiguration.GetNormalizedQuery()

				err := httpClient.SendUploadRequest(
					context.WithoutCancel(ctx),
					url.String(),
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)

				if err != nil {
					errors.LogInfoInner(ctx, err, "failed to send upload")
					uploadPipeReader.Interrupt()
				}
			}()

			if scMinPostsIntervalMs.From > 0 {
				roll := time.Duration(scMinPostsIntervalMs.roll()) * time.Millisecond
				if time.Since(lastWrite) < roll {
					time.Sleep(roll)
				}

				lastWrite = time.Now()
			}
		}
	}()

	lazyRawDownload, remoteAddr, localAddr, err := httpClient.OpenDownload(context.WithoutCancel(ctx), requestURL.String())
	if err != nil {
		return nil, err
	}

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			// skip "ok" response
			trashHeader := []byte{0, 0}
			_, err := io.ReadFull(lazyRawDownload, trashHeader)
			if err != nil {
				return nil, errors.New("failed to read initial response").Base(err)
			}

			if bytes.Equal(trashHeader, []byte("ok")) {
				return lazyRawDownload, nil
			}

			// we read some garbage byte that may not have been "ok" at
			// all. return a reader that replays what we have read so far
			reader := io.MultiReader(
				bytes.NewReader(trashHeader),
				lazyRawDownload,
			)
			readCloser := struct {
				io.Reader
				io.Closer
			}{
				Reader: reader,
				Closer: lazyRawDownload,
			}
			return readCloser, nil
		},
	}

	writer := uploadWriter{
		uploadPipeWriter,
		maxUploadSize,
	}

	conn := splitConn{
		writer:     writer,
		reader:     lazyDownload,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return stat.Connection(&conn), nil
}

// A wrapper around pipe that ensures the size limit is exactly honored.
//
// The MultiBuffer pipe accepts any single WriteMultiBuffer call even if that
// single MultiBuffer exceeds the size limit, and then starts blocking on the
// next WriteMultiBuffer call. This means that ReadMultiBuffer can return more
// bytes than the size limit. We work around this by splitting a potentially
// too large write up into multiple.
type uploadWriter struct {
	*pipe.Writer
	maxLen int32
}

func (w uploadWriter) Write(b []byte) (int, error) {
	capacity := int(w.maxLen - w.Len())
	if capacity > 0 && capacity < len(b) {
		b = b[:capacity]
	}

	buffer := buf.New()
	n, err := buffer.Write(b)
	if err != nil {
		return 0, err
	}

	err = w.WriteMultiBuffer([]*buf.Buffer{buffer})
	if err != nil {
		return 0, err
	}
	return n, nil
}
