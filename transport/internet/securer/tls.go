package securer

import (
	"context"
	gotls "crypto/tls"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type tlsConnectionSecurer struct {
	goTlsConfig      *gotls.Config
	tlsConfig        *tls.Config
	expectedProtocol string
}

func NewTLSConnectionSecurer(config *tls.Config, expectedProtocol string, tlsOptions ...tls.Option) ConnectionSecurer {
	return &tlsConnectionSecurer{
		tlsConfig:        config,
		expectedProtocol: expectedProtocol,
		goTlsConfig:      config.GetTLSConfig(tlsOptions...),
	}
}

func (s *tlsConnectionSecurer) Client(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error) {
	goTlsConfig := s.goTlsConfig.Clone()

	tls.WithDestination(dest)(goTlsConfig)

	var cn tls.Interface
	if fingerprint := tls.GetFingerprint(s.tlsConfig.Fingerprint); fingerprint != nil {
		cn = tls.UClient(conn, goTlsConfig, fingerprint).(*tls.UConn)
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
