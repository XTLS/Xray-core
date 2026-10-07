//go:build linux

package router

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// Read only the existing socket. No wrapping, duplication, dialing, deadlines
// or connection ownership changes. Closed/canceled sockets are unavailable.
func asyncDNSReadTCPInfo(conn net.Conn) asyncDNSTCPInfo {
	if conn == nil {
		return asyncDNSTCPUnavailable("unavailable")
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return asyncDNSTCPUnavailable("unsupported")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return asyncDNSTCPUnavailable("unavailable")
	}
	result := asyncDNSTCPUnavailable("unavailable")
	err = raw.Control(func(fd uintptr) {
		info, e := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if e == nil {
			result = asyncDNSTCPInfo{"available", int64(info.Rtt), int64(info.Rto), int64(info.Unacked), int64(info.Retransmits), int64(info.Total_retrans)}
		}
	})
	if err != nil {
		return asyncDNSTCPUnavailable("unavailable")
	}
	return result
}
