//go:build !linux && !freebsd && !darwin
// +build !linux,!freebsd,!darwin

package tcp

import (
	"github.com/hosemorinho412/xray-core/common/net"
	"github.com/hosemorinho412/xray-core/transport/internet/stat"
)

func GetOriginalDestination(conn stat.Connection) (net.Destination, error) {
	return net.Destination{}, nil
}
