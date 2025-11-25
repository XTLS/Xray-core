//go:build !linux
// +build !linux

package tcp

import (
	"net"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet"
)

func checkPermissions() bool {
	return false
}

func performDesync(conn net.Conn, config *internet.DesyncConfig) error {
	return errors.New("desync not supported on this platform")
}
