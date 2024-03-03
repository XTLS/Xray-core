package httpupgrade

import (
	"bufio"
	"context"
	"crypto/tls"
	"net/http"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	v2tls "github.com/xtls/xray-core/transport/internet/tls"
)

type server struct {
	config         *Config
	addConn        internet.ConnHandler
	innnerListener net.Listener
}

func (s *server) Close() error {
	return s.innnerListener.Close()
}

func (s *server) Addr() net.Addr {
	return nil
}

func (s *server) Handle(conn net.Conn) (stat.Connection, error) {
	connReader := bufio.NewReader(conn)
	req, err := http.ReadRequest(connReader)
	if err != nil {
		return nil, err
	}

	if s.config != nil {
		host := req.Host
		if len(s.config.Host) > 0 && host != s.config.Host {
			return nil, newError("bad host: ", host)
		}
		path := s.config.GetNormalizedPath()
		if req.URL.Path != path {
			return nil, newError("bad path: ", req.URL.Path)
		}
	}

	connection := strings.ToLower(req.Header.Get("Connection"))
	upgrade := strings.ToLower(req.Header.Get("Upgrade"))
	if connection != "upgrade" || upgrade != "websocket" {
		_ = conn.Close()
		return nil, newError("unrecognized request")
	}
	resp := &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: 101,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Connection", "upgrade")
	resp.Header.Set("Upgrade", "websocket")
	err = resp.Write(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return stat.Connection(conn), nil
}

func (s *server) keepAccepting() {
	for {
		conn, err := s.innnerListener.Accept()
		if err != nil {
			return
		}
		handledConn, err := s.Handle(conn)
		if err != nil {
			newError("failed to handle request").Base(err).WriteToLog()
			continue
		}
		s.addConn(handledConn)
	}
}

func listenHTTPUpgrade(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, addConn internet.ConnHandler) (internet.Listener, error) {
	transportConfiguration := streamSettings.ProtocolSettings.(*Config)
	if transportConfiguration != nil {
		if streamSettings.SocketSettings == nil {
			streamSettings.SocketSettings = &internet.SocketConfig{}
		}
		streamSettings.SocketSettings.AcceptProxyProtocol = transportConfiguration.AcceptProxyProtocol || streamSettings.SocketSettings.AcceptProxyProtocol
	}
	var listener net.Listener
	var err error
	if port == net.Port(0) { // unix
		listener, err = internet.ListenSystem(ctx, &net.UnixAddr{
			Name: address.Domain(),
			Net:  "unix",
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen unix domain socket(for HttpUpgrade) on ", address).Base(err)
		}
		newError("listening unix domain socket(for HttpUpgrade) on ", address).WriteToLog(session.ExportIDToError(ctx))
	} else { // tcp
		listener, err = internet.ListenSystem(ctx, &net.TCPAddr{
			IP:   address.IP(),
			Port: int(port),
		}, streamSettings.SocketSettings)
		if err != nil {
			return nil, newError("failed to listen TCP(for HttpUpgrade) on ", address, ":", port).Base(err)
		}
		newError("listening TCP(for HttpUpgrade) on ", address, ":", port).WriteToLog(session.ExportIDToError(ctx))
	}

	if streamSettings.SocketSettings != nil && streamSettings.SocketSettings.AcceptProxyProtocol {
		newError("accepting PROXY protocol").AtWarning().WriteToLog(session.ExportIDToError(ctx))
	}

	if config := v2tls.ConfigFromStreamSettings(streamSettings); config != nil {
		if tlsConfig := config.GetTLSConfig(); tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
		}
	}

	serverInstance := &server{
		config:         transportConfiguration,
		addConn:        addConn,
		innnerListener: listener,
	}
	go serverInstance.keepAccepting()
	return serverInstance, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, listenHTTPUpgrade))
}
