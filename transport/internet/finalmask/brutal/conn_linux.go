//go:build linux

package brutal

import (
	"context"
	"net"
	"reflect"
	"syscall"

	"github.com/pires/go-proxyproto"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func NewConn(c *Config, raw net.Conn) (net.Conn, error) {
	conn := raw
	if pc, ok := conn.(*proxyproto.Conn); ok {
		conn = pc.Raw()
	}
	if _, ok := conn.(*net.TCPConn); !ok {
		errors.LogError(context.Background(), "unsupported conn ", reflect.TypeOf(conn))
	}
	sysConn := common.Must2(conn.(*net.TCPConn).SyscallConn())
	err := sysConn.Control(func(fd uintptr) {
		if err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal"); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to set congestion")
			return
		}
		if err := syscall.SetsockoptString(int(fd), unix.IPPROTO_TCP, 23301, string(c.Params)); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to set params")
			return
		}
	})
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to control connection")
	}
	return raw, nil
}
