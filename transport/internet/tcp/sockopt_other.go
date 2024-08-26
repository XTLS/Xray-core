//go:build !linux && !freebsd && !darwin
// +build !linux,!freebsd,!darwin

package tcp

import (
	"github.com/xmplusdev/xray-core/common/net"
	"github.com/xmplusdev/xray-core/transport/internet/stat"
)

func GetOriginalDestination(conn stat.Connection) (net.Destination, error) {
	return net.Destination{}, nil
}
