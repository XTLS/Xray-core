package splithttp

import (
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

	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]DialerClient)
	}

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	isH2 := tlsConfig != nil && !(len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "http/1.1")
	isH3 := tlsConfig != nil && (len(tlsConfig.NextProtocol) == 1 && tlsConfig.NextProtocol[0] == "h3")

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

	var downloadTransport http.RoundTripper
	var uploadTransport http.RoundTripper

	if isH3 {
		dest.Network = net.Network_UDP
		quicConfig := &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       90 * time.Second,
			KeepAlivePeriod:      3 * time.Second,
			Allow0RTT:            true,
		}
		roundTripper := &http3.RoundTripper{
			TLSClientConfig: gotlsConfig,
			QUICConfig:      quicConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *gotls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
				if err != nil {
					return nil, err
				}

				var udpConn *net.UDPConn
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
					return nil, errors.New("unsupported connection type: %T", conn)
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

	sessionIdUuid := uuid.New()
	sessionId := sessionIdUuid.String()
	baseURL := requestURL.String() + sessionId

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

			seq := requestCounter
			requestCounter += 1

			go func() {
				defer requestsLimiter.Signal()

				err := httpClient.SendUploadRequest(
					context.WithoutCancel(ctx),
					baseURL+"/"+strconv.FormatInt(seq, 10),
					&buf.MultiBufferContainer{MultiBuffer: chunk},
					int64(chunk.Len()),
				)

				if err != nil {
					errors.LogInfoInner(ctx, err, "failed to send upload")
					uploadPipeReader.Interrupt()
				}
			}()

		}
	}()

	lazyRawDownload, remoteAddr, localAddr, err := httpClient.OpenDownload(context.WithoutCancel(ctx), baseURL)
	if err != nil {
		return nil, err
	}

	lazyDownload := &LazyReader{
		CreateReader: func() (io.ReadCloser, error) {
			// skip "ooooooooook" response
			trashHeader := []byte{0}
			for {
				_, err := io.ReadFull(lazyRawDownload, trashHeader)
				if err != nil {
					return nil, errors.New("failed to read initial response").Base(err)
				}
				if trashHeader[0] == 'k' {
					break
				}
			}

			return lazyRawDownload, nil
		},
	}

	// necessary in order to send larger chunks in upload
	bufferedUploadPipeWriter := buf.NewBufferedWriter(uploadPipeWriter)
	bufferedUploadPipeWriter.SetBuffered(false)

	conn := splitConn{
		writer:     bufferedUploadPipeWriter,
		reader:     lazyDownload,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return stat.Connection(&conn), nil
}
