package securer

import (
	"context"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/reality"
)

type realityConnectionSecurer struct {
	realityConfig    *reality.Config
	goRealityConfig  *goreality.Config
	expectedProtocol string
}

func NewRealityConnectionSecurer(config *reality.Config, expectedProtocol string) ConnectionSecurer {
	return &realityConnectionSecurer{
		realityConfig:    config,
		expectedProtocol: expectedProtocol,
	}
}

func (s *realityConnectionSecurer) Client(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error) {
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

func (s *realityConnectionSecurer) Server(conn net.Conn) (net.Conn, error) {
	if s.goRealityConfig == nil {
		// cache the config to avoid creating it every time
		s.goRealityConfig = s.realityConfig.GetREALITYConfig()
	}
	return reality.Server(conn, s.goRealityConfig)
}
