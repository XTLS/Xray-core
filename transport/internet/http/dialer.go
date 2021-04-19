package http

import (
	"context"
	gotls "crypto/tls"
	"net/http"
	"net/url"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/http2"
)

type dialerConf struct {
	net.Destination
	*internet.SocketConfig
	*tls.Config
}

var (
	globalDialerMap    map[dialerConf]*http.Client
	globalDialerAccess sync.Mutex
)

func getHTTPClient(ctx context.Context, dest net.Destination, tlsSettings *tls.Config, sockopt *internet.SocketConfig) (*http.Client, error) {
	globalDialerAccess.Lock()
	defer globalDialerAccess.Unlock()

	if globalDialerMap == nil {
		globalDialerMap = make(map[dialerConf]*http.Client)
	}

	if client, found := globalDialerMap[dialerConf{dest, sockopt, tlsSettings}]; found {
		return client, nil
	}

	transport := &http2.Transport{
		DialTLS: func(network string, addr string, tlsConfig *gotls.Config) (net.Conn, error) {
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

			dctx := context.Background()
			dctx = session.ContextWithID(dctx, session.IDFromContext(ctx))
			dctx = session.ContextWithOutbound(dctx, session.OutboundFromContext(ctx))

			pconn, err := internet.DialSystem(dctx, net.TCPDestination(address, port), sockopt)
			if err != nil {
				newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
				return nil, err
			}

			cn := gotls.Client(pconn, tlsConfig)
			if err := cn.Handshake(); err != nil {
				newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
				return nil, err
			}
			if !tlsConfig.InsecureSkipVerify {
				if err := cn.VerifyHostname(tlsConfig.ServerName); err != nil {
					newError("failed to dial to " + addr).Base(err).AtError().WriteToLog()
					return nil, err
				}
			}
			state := cn.ConnectionState()
			if p := state.NegotiatedProtocol; p != http2.NextProtoTLS {
				return nil, newError("http2: unexpected ALPN protocol " + p + "; want q" + http2.NextProtoTLS).AtError()
			}
			if !state.NegotiatedProtocolIsMutual {
				return nil, newError("http2: could not negotiate protocol mutually").AtError()
			}
			return cn, nil
		},
		TLSClientConfig: tlsSettings.GetTLSConfig(tls.WithDestination(dest)),
	}

	client := &http.Client{
		Transport: transport,
	}

	globalDialerMap[dialerConf{dest, sockopt, tlsSettings}] = client
	return client, nil
}

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (internet.Connection, error) {
	httpSettings := streamSettings.ProtocolSettings.(*Config)
	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		return nil, newError("TLS must be enabled for http transport.").AtWarning()
	}
	client, err := getHTTPClient(ctx, dest, tlsConfig, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	opts := pipe.OptionsFromContext(ctx)
	preader, pwriter := pipe.New(opts...)
	breader := &buf.BufferedReader{Reader: preader}
	request := &http.Request{
		Method: "PUT",
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
		Header:     make(http.Header),
	}
	// Disable any compression method from server.
	request.Header.Set("Accept-Encoding", "identity")

	response, err := client.Do(request)
	if err != nil {
		return nil, newError("failed to dial to ", dest).Base(err).AtWarning()
	}
	if response.StatusCode != 200 {
		return nil, newError("unexpected status", response.StatusCode).AtWarning()
	}

	bwriter := buf.NewBufferedWriter(pwriter)
	common.Must(bwriter.SetBuffered(false))
	return cnc.NewConnection(
		cnc.ConnectionOutput(response.Body),
		cnc.ConnectionInput(bwriter),
		cnc.ConnectionOnClose(common.ChainedClosable{breader, bwriter, response.Body}),
	), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
