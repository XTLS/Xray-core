package securer

import (
	"context"
	gotls "crypto/tls"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type tlsConnectionSecurer struct {
	tlsConfig        *tls.Config
	expectedProtocol string
	nextProtos       []string
}

func (s tlsConnectionSecurer) SecureClient(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error) {
	var goTlsConfig *gotls.Config
	if s.nextProtos != nil {
		goTlsConfig = s.tlsConfig.GetTLSConfig(tls.WithDestination(dest), tls.WithNextProto(s.nextProtos...))
	} else {
		goTlsConfig = s.tlsConfig.GetTLSConfig(tls.WithDestination(dest))
	}

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
