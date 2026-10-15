//go:build !android

package realm

import (
	"context"

	"github.com/libp2p/go-nat"
)

func discoverGateway(ctx context.Context) (nat.NAT, error) {
	return nat.DiscoverGateway(ctx)
}
