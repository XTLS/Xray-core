package securer

import (
	"context"
	gotls "crypto/tls"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type tlsConnectionSecurer struct {
	goTlsConfig      *gotls.Config
	fingerprint      *utls.ClientHelloID
	expectedProtocol string
}

func NewTLSConnectionSecurer(config *tls.Config, expectedProtocol string) ConnectionSecurer {
	return &tlsConnectionSecurer{
		goTlsConfig:      config.GetTLSConfig(),
		fingerprint:      tls.GetFingerprint(config.Fingerprint),
		expectedProtocol: expectedProtocol,
	}
}

func (s *tlsConnectionSecurer) Client(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error) {
	goTlsConfig := s.goTlsConfig.Clone()

	tls.WithDestination(dest)(goTlsConfig)

	var cn tls.Interface
	if s.fingerprint != nil {
		cn = tls.UClient(conn, goTlsConfig, s.fingerprint).(*tls.UConn)
	} else {
		cn = tls.Client(conn, goTlsConfig).(*tls.Conn)
	}
	if err := cn.Handshake(); err != nil {
		return nil, err
	}
	if !goTlsConfig.InsecureSkipVerify {
		if err := cn.VerifyHostname(goTlsConfig.ServerName); err != nil {
			return nil, err
		}
	}

	if s.expectedProtocol != "" && cn.NegotiatedProtocol() != s.expectedProtocol {
		return nil, newError("unexpected ALPN protocol " + cn.NegotiatedProtocol() + "; required " + s.expectedProtocol).AtError()
	}

	return cn, nil
}

func (s *tlsConnectionSecurer) Server(conn net.Conn) (net.Conn, error) {
	return tls.Server(conn, s.goTlsConfig), nil
}
