package outbound

import (
	"context"
	"os"

	"github.com/GFW-knocker/Xray-core/common/errors"
	"github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/transport/internet"
	"github.com/GFW-knocker/Xray-core/transport/internet/stat"
	"github.com/sagernet/sing/common/uot"
)

func (h *Handler) getUoTConnection(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	if dest.Address == nil {
		return nil, errors.New("nil destination address")
	}
	if !dest.Address.Family().IsDomain() {
		return nil, os.ErrInvalid
	}
	var uotVersion int
	if dest.Address.Domain() == uot.MagicAddress {
		uotVersion = uot.Version
	} else if dest.Address.Domain() == uot.LegacyMagicAddress {
		uotVersion = uot.LegacyVersion
	} else {
		return nil, os.ErrInvalid
	}
	packetConn, err := internet.ListenSystemPacket(ctx, &net.UDPAddr{IP: net.AnyIP.IP(), Port: 0}, h.streamSettings.SocketSettings)
	if err != nil {
		return nil, errors.New("unable to listen socket").Base(err)
	}
	conn := uot.NewServerConn(packetConn, uotVersion)
	return h.getStatCouterConnection(conn), nil
}
