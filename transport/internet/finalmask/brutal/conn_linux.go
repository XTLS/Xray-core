//go:build linux

package brutal

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func NewConn(c *Config, raw net.Conn) (net.Conn, error) {
	conn, ok := raw.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		errors.LogError(context.Background(), fmt.Sprintf("failed to get syscall conn, type=%T", raw))
		return raw, nil
	}
	sysConn, err := conn.SyscallConn()
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to get syscall conn")
		return raw, nil
	}
	err = sysConn.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to set congestion")
			return
		}
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, 23301, string(c.Params)); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to set params")
			return
		}
	})
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to control connection")
	}
	return raw, nil
}
