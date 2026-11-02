//go:build linux || android

package proxy

import (
	"net"

	"golang.org/x/sys/unix"
)

// tcpBytesReceived returns the number of bytes received on conn from its peer.
func tcpBytesReceived(conn net.Conn) (int64, bool) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var (
		n       int64
		sockErr error
	)
	if cerr := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			sockErr = err
			return
		}
		n = int64(info.Bytes_received)
	}); cerr != nil || sockErr != nil {
		return 0, false
	}
	return n, true
}
