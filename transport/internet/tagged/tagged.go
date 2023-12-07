package tagged

import (
	"context"

	"github.com/4nd3r5on/Xray-core/common/net"
)

type DialFunc func(ctx context.Context, dest net.Destination, tag string) (net.Conn, error)

var Dialer DialFunc
