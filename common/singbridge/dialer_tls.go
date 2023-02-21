package singbridge

import (
	"context"
	gotls "crypto/tls"
	"os"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/tls"
)

type XrayTLSDialer struct {
	dialer     internet.Dialer
	clientFunc tls.CustomClientFunc
}

func NewTLSDialer(dialer internet.Dialer, clientFunc tls.CustomClientFunc) *XrayTLSDialer {
	return &XrayTLSDialer{dialer, clientFunc}
}

func (d *XrayTLSDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	var internetTLSConfig *tls.Config
	var tlsConfig *gotls.Config
	conn, err := d.dialer.Dial(tls.ContextWithCustomClient(ctx, func(conn net.Conn, xrayConfig *tls.Config, config *gotls.Config) net.Conn {
		internetTLSConfig = xrayConfig
		tlsConfig = config
		return conn
	}), ToDestination(destination, ToNetwork(network)))
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, E.New("missing TLS config")
	}
	return d.clientFunc(conn, internetTLSConfig, tlsConfig), nil
}

func (d *XrayTLSDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
