//go:build windows

package fragment

import (
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

// msgOOB is the Windows MSG_OOB flag value (0x1); x/sys/windows does not
// export it.
const msgOOB = 0x1

func setTTL(conn net.Conn, ttl int) error {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
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
	var ttl int
	var getErr error
	err = raw.Control(func(fd uintptr) {
		ttl, getErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL)
	})
	if err != nil {
		return 0, err
	}
	return ttl, getErr
}

// sendOOB sends b with the MSG_OOB flag (0x1). The flag is passed directly
// to WSASend, because Go's net.Conn API has no way to set send flags.
func sendOOB(conn net.Conn, b []byte) (int, error) {
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		var buf windows.WSABuf
		buf.Len = uint32(len(b))
		buf.Buf = &b[0]
		var sent uint32
		sendErr = windows.WSASend(windows.Handle(fd), &buf, 1, &sent, msgOOB, nil, nil)
		n = int(sent)
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
		setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_NODELAY, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}
