package securer

import (
	"context"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/tls"
)

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

type ConnectionSecurer interface {
	// secures the given connection with security protocols such as TLS, REALITY, etc.
	Client(ctx context.Context, dest net.Destination, conn net.Conn) (net.Conn, error)
	// secures the given connection with security protocols such as TLS, REALITY, etc.
	Server(conn net.Conn) (net.Conn, error)
}

func NewConnectionSecurerFromStreamSettings(streamSettings *internet.MemoryStreamConfig, expectedProtocol string, tlsOptions ...tls.Option) ConnectionSecurer {
	if tlsConfig := tls.ConfigFromStreamSettings(streamSettings); tlsConfig != nil {
		return NewTLSConnectionSecurer(tlsConfig, expectedProtocol)
	}

	if realityConfig := reality.ConfigFromStreamSettings(streamSettings); realityConfig != nil {
		return NewRealityConnectionSecurer(realityConfig, expectedProtocol)
	}

	return nil
}
