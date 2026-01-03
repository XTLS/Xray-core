//go:build linux

package xpool

import (
	"net"
	"syscall"
)

const (
	TCP_USER_TIMEOUT = 18
	TCP_KEEPIDLE     = 4
	TCP_KEEPINTVL    = 5
	TCP_KEEPCNT      = 6
)

func configureTCP(conn net.Conn, cfg *SocketConfig) error {
	rawConn, err := conn.(interface{ SyscallConn() (syscall.RawConn, error) }).SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	err = rawConn.Control(func(fd uintptr) {
		fdInt := int(fd)

		if cfg.UserTimeout > 0 {
			syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, TCP_USER_TIMEOUT, cfg.UserTimeout)
		}

		// KeepAlive
		syscall.SetsockoptInt(fdInt, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
		syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, TCP_KEEPIDLE, cfg.KeepAliveIdle)
		syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, TCP_KEEPINTVL, cfg.KeepAliveIntv)
		syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, TCP_KEEPCNT, cfg.KeepAliveCnt)

		if cfg.NoDelay {
			syscall.SetsockoptInt(fdInt, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		}
	})

	if err != nil {
		return err
	}
	return sockErr
}
