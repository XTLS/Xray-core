//go:build !windows && !plan9 && !js

package fragment

import (
	"net"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func setTTL(conn net.Conn, ttl int) error {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			if addr.IP.To4() != nil {
				setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
			} else {
				setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
			}
		default:
			setErr = errors.New("unsupported remote address type")
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

func getTTL(conn net.Conn) (int, error) {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var ttl, getErrNo int
	var getErr error
	err = raw.Control(func(fd uintptr) {
		switch addr := conn.RemoteAddr().(type) {
		case *net.TCPAddr:
			if addr.IP.To4() != nil {
				ttl, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL)
			} else {
				ttl, getErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS)
			}
		default:
			getErrNo = 1
		}
	})
	if err != nil {
		return 0, err
	}
	if getErr != nil {
		return 0, getErr
	}
	if getErrNo != 0 {
		return 0, errors.New("unsupported remote address type")
	}
	return ttl, nil
}

func sendOOB(conn net.Conn, b []byte) (int, error) {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		n, sendErr = unix.SendmsgN(int(fd), b, nil, nil, unix.MSG_OOB)
	})
	if err != nil {
		return 0, err
	}
	return n, sendErr
}

func enableNoDelay(conn net.Conn) error {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}
