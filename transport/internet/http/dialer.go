package http

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
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

type dialerConf struct {
	net.Destination
	*internet.MemoryStreamConfig
}

var (
	globalDialerMap    map[dialerConf]*http.Client
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (*http.Client, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*http.Client)
	}

	httpSettings := streamSettings.ProtocolSettings.(*Config)
	tlsConfigs := tls.ConfigFromStreamSettings(streamSettings)
	realityConfigs := reality.ConfigFromStreamSettings(streamSettings)
	if tlsConfigs == nil && realityConfigs == nil {
		return nil, errors.New("TLS or REALITY must be enabled for http transport.").AtWarning()
	}
	isH3 := tlsConfigs != nil && (len(tlsConfigs.NextProtocol) == 1 && tlsConfigs.NextProtocol[0] == "h3")
	if isH3 {
		dest.Network = net.Network_UDP
	}
	sockopt := streamSettings.SocketSettings

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client, nil
	}

	var transport http.RoundTripper
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
			TLSClientConfig: tlsConfigs.GetTLSConfig(tls.WithDestination(dest)),
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
		transport = roundTripper
	} else {
		transportH2 := &http2.Transport{
			DialTLSContext: func(hctx context.Context, string, addr string, tlsConfig *gotls.Config) (net.Conn, error) {
				rawHost, rawPort, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				if len(rawPort) == 0 {
					rawPort = "443"
				}
				port, err := net.PortFromString(rawPort)
				if err != nil {
					return nil, err
				}
				address := net.ParseAddress(rawHost)

				hctx = c.ContextWithID(hctx, c.IDFromContext(ctx))
				hctx = session.ContextWithOutbounds(hctx, session.OutboundsFromContext(ctx))
				hctx = session.ContextWithTimeoutOnly(hctx, true)

				pconn, err := internet.DialSystem(hctx, net.TCPDestination(address, port), sockopt)
				if err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}

				if realityConfigs != nil {
					return reality.UClient(pconn, realityConfigs, hctx, dest)
				}

				var cn tls.Interface
				if fingerprint := tls.GetFingerprint(tlsConfigs.Fingerprint); fingerprint != nil {
					cn = tls.UClient(pconn, tlsConfig, fingerprint).(*tls.UConn)
				} else {
					cn = tls.Client(pconn, tlsConfig).(*tls.Conn)
				}
				if err := cn.HandshakeContext(ctx); err != nil {
					errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
					return nil, err
				}
				if !tlsConfig.InsecureSkipVerify {
					if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
						errors.LogErrorInner(ctx, err, "failed to dial to "+addr)
						return nil, err
					}
				}
				negotiatedProtocol := cn.NegotiatedProtocol()
				if negotiatedProtocol != http2.NextProtoTLS {
					return nil, errors.New("http2: unexpected ALPN protocol " + negotiatedProtocol + "; want q" + http2.NextProtoTLS).AtError()
				}
				return cn, nil
			},
		}
		if tlsConfigs != nil {
			transportH2.TLSClientConfig = tlsConfigs.GetTLSConfig(tls.WithDestination(dest))
		}
		if httpSettings.IdleTimeout > 0 || httpSettings.HealthCheckTimeout > 0 {
			transportH2.ReadIdleTimeout = time.Second * time.Duration(httpSettings.IdleTimeout)
			transportH2.PingTimeout = time.Second * time.Duration(httpSettings.HealthCheckTimeout)
		}
		transport = transportH2
	}

	client := &http.Client{
		Transport: transport,
	}

	globalDialerMap[dialerConf{dest, streamSettings}] = client
	return client, nil
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	httpSettings := streamSettings.ProtocolSettings.(*Config)
	client, err := getHTTPClient(ctx, dest, streamSettings)
	if err != nil {
		return nil, err
	}

	opts := pipe.OptionsFromContext(ctx)
	preader, pwriter := pipe.New(opts...)
	breader := &buf.BufferedReader{Reader: preader}

	httpMethod := "PUT"
	if httpSettings.Method != "" {
		httpMethod = httpSettings.Method
	}

	httpHeaders := make(http.Header)

	for _, httpHeader := range httpSettings.Header {
		for _, httpHeaderValue := range httpHeader.Value {
			httpHeaders.Set(httpHeader.Name, httpHeaderValue)
		}
	}

	Host := httpSettings.getRandomHost()
	if Host == "" && net.ParseAddress(dest.NetAddr()).Family().IsDomain() {
		Host = dest.Address.String()
	} else if Host == "" {
		Host = "www.example.com"
	}

	request := &http.Request{
		Method: httpMethod,
		Host:   Host,
		Body:   breader,
		URL: &url.URL{
			Scheme: "https",
			Host:   dest.NetAddr(),
			Path:   httpSettings.getNormalizedPath(),
		},
		Header: httpHeaders,
	}
	// Disable any compression method from server.
	request.Header.Set("Accept-Encoding", "identity")

	wrc := &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		response, err := client.Do(request)
		if err != nil || response.StatusCode != 200 {
			if err != nil {
				errors.LogWarningInner(ctx, err, "failed to dial to ", dest)
			} else {
				errors.LogWarning(ctx, "unexpected status ", response.StatusCode)
			}
			wrc.Close()
			{
				// Abandon `client` if `client.Do(request)` failed
				// See https://github.com/golang/go/issues/30702
				globalDialerAccess.Lock()
				if globalDialerMap[dialerConf{dest, streamSettings}] == client {
					delete(globalDialerMap, dialerConf{dest, streamSettings})
				}
				globalDialerAccess.Unlock()
			}
			return
		}
		wrc.Set(response.Body)
	}()

	bwriter := buf.NewBufferedWriter(pwriter)
	common.Must(bwriter.SetBuffered(false))
	return cnc.NewConnection(
		cnc.ConnectionOutput(wrc),
		cnc.ConnectionInput(bwriter),
		cnc.ConnectionOnClose(common.ChainedClosable{breader, bwriter, wrc}),
	), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}

type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.ReadCloser = rc
	defer func() {
		if recover() != nil {
			rc.Close()
		}
	}()
	close(w.Wait)
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

func (w *WaitReadCloser) Close() error {
	if w.ReadCloser != nil {
		return w.ReadCloser.Close()
	}
	defer func() {
		if recover() != nil && w.ReadCloser != nil {
			w.ReadCloser.Close()
		}
	}()
	close(w.Wait)
	return nil
}
