//go:build !linux

package xdns

import (
	"net"
	"syscall"
)

func resolverSocketControl(_ net.PacketConn) func(network, address string, c syscall.RawConn) error {
	return nil
}
