package internet

import (
	"syscall"
)

const (
	TCP_FASTOPEN = 15
)

func setTFO(fd syscall.Handle, tfo int) error {
	if tfo > 0 {
		tfo = 1
	}
	if tfo >= 0 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, tfo); err != nil {
			return err
		}
	}
	return nil
}

func applyOutboundSocketOptions(network string, address string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return newError("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return newError("failed to unset SO_KEEPALIVE", err)
			}
		}
		if config.TcpNoDelay {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
				return newError("failed to set TCP_NODELAY", err)
			}
		}
	}

	return nil
}

func applyInboundSocketOptions(network string, fd uintptr, config *SocketConfig) error {
	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return newError("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return newError("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

	return nil
}

func bindAddr(fd uintptr, ip []byte, port uint32) error {
	return nil
}

func setReuseAddr(fd uintptr) error {
	return nil
}

func setReusePort(fd uintptr) error {
	return nil
}
