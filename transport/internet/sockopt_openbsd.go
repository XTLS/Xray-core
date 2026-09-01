//go:build openbsd
// +build openbsd

package internet

import (
	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/sys/unix"
)

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	return nil
}

func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	if config.ReceiveOriginalDestAddress && isUDPSocket(network) {
		// Only the options matching the socket's address family are accepted,
		// so one of the two pairs succeeding is enough.
		err6 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		if err6 == nil {
			err6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVDSTPORT, 1)
		}
		err4 := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1)
		if err4 == nil {
			err4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTPORT, 1)
		}
		if err4 != nil && err6 != nil {
			return errors.New("failed to enable receiving the original destination").Base(err4)
		}
	}
	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}
