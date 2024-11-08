package http

import (
	"context"
	gotls "crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type Listener struct {
	server   *http.Server
	h3server *http3.Server
	handler  internet.ConnHandler
	local    net.Addr
	config   *Config
	isH3     bool
}

func (l *Listener) Addr() net.Addr {
	return l.local
}

func (l *Listener) Close() error {
	if l.h3server != nil {
		if err := l.h3server.Close(); err != nil {
			return err
		}
	} else if l.server != nil {
		return l.server.Close()
	}
	return errors.New("listener does not have an HTTP/3 server or h2 server")
}

type flushWriter struct {
	w io.Writer
	d *done.Instance
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	if fw.d.Done() {
		return 0, io.ErrClosedPipe
	}

	defer func() {
		if recover() != nil {
			fw.d.Close()
			err = io.ErrClosedPipe
		}
	}()

	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok && err == nil {
		f.Flush()
	}
	return
}

func (l *Listener) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	host := request.Host
	if !l.config.isValidHost(host) {
		writer.WriteHeader(404)
		return
	}
	path := l.config.getNormalizedPath()
	if !strings.HasPrefix(request.URL.Path, path) {
		writer.WriteHeader(404)
		return
	}

	writer.Header().Set("Cache-Control", "no-store")

	for _, httpHeader := range l.config.Header {
		for _, httpHeaderValue := range httpHeader.Value {
			writer.Header().Set(httpHeader.Name, httpHeaderValue)
		}
	}

	writer.WriteHeader(200)
	if f, ok := writer.(http.Flusher); ok {
		f.Flush()
	}

	remoteAddr := l.Addr()
	dest, err := net.ParseDestination(request.RemoteAddr)
	if err != nil {
		errors.LogInfoInner(context.Background(), err, "failed to parse request remote addr: ", request.RemoteAddr)
	} else {
		remoteAddr = &net.TCPAddr{
			IP:   dest.Address.IP(),
			Port: int(dest.Port),
		}
	}

	forwardedAddress := http_proto.ParseXForwardedFor(request.Header)
	if len(forwardedAddress) > 0 && forwardedAddress[0].Family().IsIP() {
		remoteAddr = &net.TCPAddr{
			IP:   forwardedAddress[0].IP(),
			Port: 0,
		}
	}

	done := done.New()
	conn := cnc.NewConnection(
		cnc.ConnectionOutput(request.Body),
		cnc.ConnectionInput(flushWriter{w: writer, d: done}),
		cnc.ConnectionOnClose(common.ChainedClosable{done, request.Body}),
		cnc.ConnectionLocalAddr(l.Addr()),
		cnc.ConnectionRemoteAddr(remoteAddr),
	)
	l.handler(conn)
	<-done.Wait()
}

func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	httpSettings := streamSettings.ProtocolSettings.(*Config)
	config := tls.ConfigFromStreamSettings(streamSettings)
	var tlsConfig *gotls.Config
	if config == nil {
		tlsConfig = &gotls.Config{}
	} else {
		tlsConfig = config.GetTLSConfig()
	}
	isH3 := len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "h3"
	listener := &Listener{
		handler: handler,
		config:  httpSettings,
		isH3:    isH3,
	}
	if port == net.Port(0) { // unix
		listener.local = &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}
	} else if isH3 { // udp
		listener.local = &net.UDPAddr{
			IP:   address.IP(),
			Port: int(port),
		}
	} else {
		listener.local = &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		errors.LogWarning(ctx, "accepting PROXY protocol")
	}

	if isH3 {
		Conn, err := internet.ListenSystemPacket(context.Background(), listener.local, streamSettings.SocketSettings)
		if err != nil {
			return nil, errors.New("failed to listen UDP(for SH3) on ", address, ":", port).Base(err)
		}
		h3listener, err := quic.ListenEarly(Conn, tlsConfig, nil)
		if err != nil {
			return nil, errors.New("failed to listen QUIC(for SH3) on ", address, ":", port).Base(err)
		}
		errors.LogInfo(ctx, "listening QUIC(for SH3) on ", address, ":", port)

		listener.h3server = &http3.Server{
			Handler: listener,
		}
		go func() {
			if err := listener.h3server.ServeListener(h3listener); err != nil {
				errors.LogWarningInner(ctx, err, "failed to serve http3 for splithttp")
			}
		}()
	} else {
		var server *http.Server
		if config == nil {
			h2s := &http2.Server{}

			server = &http.Server{
				Addr:              serial.Concat(address, ":", port),
				Handler:           h2c.NewHandler(listener, h2s),
				ReadHeaderTimeout: time.Second * 4,
			}
		} else {
			server = &http.Server{
				Addr:              serial.Concat(address, ":", port),
				TLSConfig:         config.GetTLSConfig(tls.WithNextProto("h2")),
				Handler:           listener,
				ReadHeaderTimeout: time.Second * 4,
			}
		}

		listener.server = server
		go func() {
			var streamListener net.Listener
			var err error
			if port == net.Port(0) { // unix
				streamListener, err = internet.ListenSystem(ctx, &net.UnixAddr{
					Name: address.Domain(),
					Net:  "unix",
				}, streamSettings.SocketSettings)
				if err != nil {
					errors.LogErrorInner(ctx, err, "failed to listen on ", address)
					return
				}
			} else { // tcp
				streamListener, err = internet.ListenSystem(ctx, &net.TCPAddr{
					IP:   address.IP(),
					Port: int(port),
				}, streamSettings.SocketSettings)
				if err != nil {
					errors.LogErrorInner(ctx, err, "failed to listen on ", address, ":", port)
					return
				}
			}

			if config == nil {
				if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
					streamListener = goreality.NewListener(streamListener, config.GetREALITYConfig())
				}
				err = server.Serve(streamListener)
				if err != nil {
					errors.LogInfoInner(ctx, err, "stopping serving H2C or REALITY H2")
				}
			} else {
				err = server.ServeTLS(streamListener, "", "")
				if err != nil {
					errors.LogInfoInner(ctx, err, "stopping serving TLS H2")
				}
			}
		}()
	}

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
