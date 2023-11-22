package securer

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/reality"
)

type realityConnectionSecurer struct {
	realityConfig    *reality.Config
	expectedProtocol string
}

func (s realityConnectionSecurer) SecureClient(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error) {
	conn, err := reality.UClient(conn, s.realityConfig, ctx, dest)
	if err != nil {
		return nil, err
	}

	if s.expectedProtocol != "" {
		cn := conn.(*reality.UConn)

		if cn.NegotiatedProtocol() != s.expectedProtocol {
			return nil, newError("unexpected ALPN protocol " + cn.NegotiatedProtocol() + "; required " + s.expectedProtocol).AtError()
		}
	}

	return conn, nil
}
