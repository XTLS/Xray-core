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
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTADDR, 1); err != nil {
			return errors.New("failed to set IP_RECVDSTADDR").Base(err)
		}
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVDSTPORT, 1); err != nil {
			return errors.New("failed to set IP_RECVDSTPORT").Base(err)
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
