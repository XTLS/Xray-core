package singbridge

import (
	"context"
	"os"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

var _ N.Dialer = (*XrayDialer)(nil)

type XrayDialer struct {
	internet.Dialer
}

func NewDialer(dialer internet.Dialer) *XrayDialer {
	return &XrayDialer{dialer}
}

func (d *XrayDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.Dial(ctx, ToDestination(destination, ToNetwork(network)))
}

func (d *XrayDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
