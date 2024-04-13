package http

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
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
		return nil, newError("TLS or REALITY must be enabled for http transport.").AtWarning()
	}
	sockopt := streamSettings.SocketSettings

	if client, found := globalDialerMap[dialerConf{dest, streamSettings}]; found {
		return client, nil
	}

	transport := &http2.Transport{
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

			hctx = session.ContextWithID(hctx, session.IDFromContext(ctx))
			hctx = session.ContextWithOutbound(hctx, session.OutboundFromContext(ctx))
			hctx = session.ContextWithTimeoutOnly(hctx, true)

			pconn, err := internet.DialSystem(hctx, net.TCPDestination(address, port), sockopt)
			if err != nil {
				newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
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
				newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
				return nil, err
			}
			if !tlsConfig.InsecureSkipVerify {
				if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
					newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
					return nil, err
				}
			}
			negotiatedProtocol := cn.NegotiatedProtocol()
			if negotiatedProtocol != http2.NextProtoTLS {
				return nil, newError("http2: unexpected ALPN protocol " + negotiatedProtocol + "; want q" + http2.NextProtoTLS).AtError()
			}
			return cn, nil
		},
	}

	if tlsConfigs != nil {
		transport.TLSClientConfig = tlsConfigs.GetTLSConfig(tls.WithDestination(dest))
	}

	if httpSettings.IdleTimeout > 0 || httpSettings.HealthCheckTimeout > 0 {
		transport.ReadIdleTimeout = time.Second * time.Duration(httpSettings.IdleTimeout)
		transport.PingTimeout = time.Second * time.Duration(httpSettings.HealthCheckTimeout)
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

	request := &http.Request{
		Method: httpMethod,
		Host:   httpSettings.getRandomHost(),
		Body:   breader,
		URL: &url.URL{
			Scheme: "https",
			Host:   dest.NetAddr(),
			Path:   httpSettings.getNormalizedPath(),
		},
		Proto:      "HTTP/2",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     httpHeaders,
	}
	// Disable any compression method from server.
	request.Header.Set("Accept-Encoding", "identity")

	wrc := &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		response, err := client.Do(request)
		if err != nil {
			newError("failed to dial to ", dest).Base(err).AtWarning().WriteToLog(session.ExportIDToError(ctx))
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
		if response.StatusCode != 200 {
			newError("unexpected status", response.StatusCode).AtWarning().WriteToLog(session.ExportIDToError(ctx))
			wrc.Close()
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
