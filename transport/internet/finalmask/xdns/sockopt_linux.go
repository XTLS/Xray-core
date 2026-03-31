//go:build linux

package xdns

import (
	"context"
	"net"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

// resolverSocketControl reads outbound socket options (SO_MARK, SO_BINDTODEVICE)
// from the raw PacketConn and returns a Control function that applies them to
// resolver sockets. This ensures resolver traffic respects the same routing
// policy and interface binding as the original outbound connection.
func resolverSocketControl(raw net.PacketConn) func(network, address string, c syscall.RawConn) error {
	sc, ok := raw.(syscall.Conn)
	if !ok {
		return nil
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return nil
	}

	var mark int
	var iface string
	rawConn.Control(func(fd uintptr) {
		v, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK)
		if err == nil && v != 0 {
			mark = v
		}
		s, err := unix.GetsockoptString(int(fd), syscall.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if err == nil && s != "" {
			iface = s
		}
	})

	if mark == 0 && iface == "" {
		return nil
	}

	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			if mark != 0 {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
					errors.LogInfo(context.Background(), "xdns: failed to set SO_MARK on resolver socket: ", err)
				}
			}
			if iface != "" {
				if err := syscall.BindToDevice(int(fd), iface); err != nil {
					errors.LogInfo(context.Background(), "xdns: failed to bind resolver socket to interface: ", err)
				}
			}
		})
	}
}
