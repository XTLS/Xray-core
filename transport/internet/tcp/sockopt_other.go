// +build !linux,!freebsd
// +build !confonly

package tcp

import (
	"github.com/xtls/xray-core/v1/common/net"
	"github.com/xtls/xray-core/v1/transport/internet"
)

func GetOriginalDestination(conn internet.Connection) (net.Destination, error) {
	return net.Destination{}, nil
}
