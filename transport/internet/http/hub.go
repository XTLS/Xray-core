package http

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/net/cnc"
	http_proto "github.com/xtls/xray-core/common/protocol/http"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type Listener struct {
	server  *http.Server
	handler internet.ConnHandler
	local   net.Addr
	config  *Config
	locker  *internet.FileLocker // for unix domain socket
}

func (l *Listener) Addr() net.Addr {
	return l.local
}

func (l *Listener) Close() error {
	if l.locker != nil {
		l.locker.Release()
	}
	return l.server.Close()
}

type flushWriter struct {
	w io.Writer
	d *done.Instance
}

func (fw flushWriter) Write(p []byte) (n int, err error) {
	if fw.d.Done() {
		return 0, io.ErrClosedPipe
	}

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
	writer.WriteHeader(200)
	if f, ok := writer.(http.Flusher); ok {
		f.Flush()
	}

	remoteAddr := l.Addr()
	dest, err := net.ParseDestination(request.RemoteAddr)
	if err != nil {
		newError("failed to parse request remote addr: ", request.RemoteAddr).Base(err).WriteToLog()
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
	var listener *Listener
	if port == net.Port(0) { // unix
		listener = &Listener{
			handler: handler,
			local: &net.UnixAddr{
				Name: address.Domain(),
				Net:  "unix",
			},
			config: httpSettings,
		}
	} else { // tcp
		listener = &Listener{
			handler: handler,
			local: &net.TCPAddr{
				IP:   address.IP(),
				Port: int(port),
			},
			config: httpSettings,
		}
	}

	var server *http.Server
	config := tls.ConfigFromStreamSettings(streamSettings)
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

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
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
				newError("failed to listen on ", address).Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}
			locker := ctx.Value(address.Domain())
			if locker != nil {
				listener.locker = locker.(*internet.FileLocker)
			}
		} else { // tcp
			streamListener, err = internet.ListenSystem(ctx, &net.TCPAddr{
				IP:   address.IP(),
				Port: int(port),
			}, streamSettings.SocketSettings)
			if err != nil {
				newError("failed to listen on ", address, ":", port).Base(err).AtError().WriteToLog(session.ExportIDToError(ctx))
				return
			}
		}

		if config == nil {
			err = server.Serve(streamListener)
			if err != nil {
				newError("stopping serving H2C").Base(err).WriteToLog(session.ExportIDToError(ctx))
			}
		} else {
			err = server.ServeTLS(streamListener, "", "")
			if err != nil {
				newError("stopping serving TLS").Base(err).WriteToLog(session.ExportIDToError(ctx))
			}
		}
	}()

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
