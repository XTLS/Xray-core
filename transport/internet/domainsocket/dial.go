//go:build !windows && !wasm
// +build !windows,!wasm

package domainsocket

import (
	"context"

	"github.com/xmplusdev/xray-core/common"
	"github.com/xmplusdev/xray-core/common/errors"
	"github.com/xmplusdev/xray-core/common/net"
	"github.com/xmplusdev/xray-core/transport/internet"
	"github.com/xmplusdev/xray-core/transport/internet/reality"
	"github.com/xmplusdev/xray-core/transport/internet/stat"
	"github.com/xmplusdev/xray-core/transport/internet/tls"
)

func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	settings := streamSettings.ProtocolSettings.(*Config)
	addr, err := settings.GetUnixAddr()
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, errors.New("failed to dial unix: ", settings.Path).Base(err).AtWarning()
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		return tls.Client(conn, config.GetTLSConfig(tls.WithDestination(dest))), nil
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		return reality.UClient(conn, config, ctx, dest)
	}

	return conn, nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
