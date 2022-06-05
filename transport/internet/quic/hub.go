package quic

import (
	"context"
	"io"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Listener is an internet.Listener that listens for TCP connections.
type Listener struct {
	rawConn  *sysConn
	listener quic.Listener
	done     *done.Instance
	addConn  internet.ConnHandler
}

func (l *Listener) acceptStreams(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			newError("failed to accept stream").Base(err).WriteToLog()
			select {
			case <-conn.Context().Done():
				return
			case <-l.done.Wait():
				if err := conn.CloseWithError(0, ""); err != nil {
					newError("failed to close connection").Base(err).WriteToLog()
				}
				return
			default:
				time.Sleep(time.Second)
				continue
			}
		}

		conn := &interConn{
			stream: stream,
			local:  conn.LocalAddr(),
			remote: conn.RemoteAddr(),
		}

		l.addConn(conn)
	}
}

func (l *Listener) keepAccepting() {
	for {
		conn, err := l.listener.Accept(context.Background())
		if err != nil {
			newError("failed to accept QUIC connection").Base(err).WriteToLog()
			if l.done.Done() {
				break
			}
			time.Sleep(time.Second)
			continue
		}
		go l.acceptStreams(conn)
	}
}

// Addr implements internet.Listener.Addr.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close implements internet.Listener.Close.
func (l *Listener) Close() error {
	l.done.Close()
	l.listener.Close()
	l.rawConn.Close()
	return nil
}

// Listen creates a new Listener based on configurations.
func Listen(ctx context.Context, address net.Address, port net.Port, streamSettings *internet.MemoryStreamConfig, handler internet.ConnHandler) (internet.Listener, error) {
	if address.Family().IsDomain() {
		return nil, newError("domain address is not allows for listening quic")
	}

	tlsConfig := tls.ConfigFromStreamSettings(streamSettings)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			Certificate: []*tls.Certificate{tls.ParseCertificate(cert.MustGenerate(nil, cert.DNSNames(internalDomain), cert.CommonName(internalDomain)))},
		}
	}

	config := streamSettings.ProtocolSettings.(*Config)
	rawConn, err := internet.ListenSystemPacket(context.Background(), &net.UDPAddr{
		IP:   address.IP(),
		Port: int(port),
	}, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		ConnectionIDLength:    12,
		KeepAlive:             false,
		MaxIncomingStreams:    32,
		MaxIncomingUniStreams: -1,
		Tracer: qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			return &QlogWriter{connID: connID}
		}),
	}

	conn, err := wrapSysConn(rawConn.(*net.UDPConn), config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	qListener, err := quic.Listen(conn, tlsConfig.GetTLSConfig(), quicConfig)
	if err != nil {
		conn.Close()
		return nil, err
	}

	listener := &Listener{
		done:     done.New(),
		rawConn:  conn,
		listener: qListener,
		addConn:  handler,
	}

	go listener.keepAccepting()

	return listener, nil
}

func init() {
	common.Must(internet.RegisterTransportListener(protocolName, Listen))
}
