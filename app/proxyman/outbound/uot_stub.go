//go:build !go1.18

package outbound

import (
	"context"
	"os"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func (h *Handler) getUoTConnection(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return nil, os.ErrInvalid
}
