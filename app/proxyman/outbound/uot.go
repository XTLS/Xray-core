//go:build go1.18

package outbound

import (
	"context"
	"os"

	"github.com/sagernet/sing/common/uot"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (h *Handler) getUoTConnection(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if !dest.Address.Family().IsDomain() || dest.Address.Domain() != uot.UOTMagicAddress {
		return nil, os.ErrInvalid
	}
	packetConn, err := internet.ListenSystemPacket(ctx, &net.UDPAddr{IP: net.AnyIP.IP(), Port: 0}, h.streamSettings.SocketSettings)
	if err != nil {
		return nil, newError("unable to listen socket").Base(err)
	}
	conn := uot.NewServerConn(packetConn)
	return h.getStatCouterConnection(conn), nil
}
