package internet

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
)

const (
	TCP_FASTOPEN    = 15
	IP_UNICAST_IF   = 31
	IPV6_UNICAST_IF = 31
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
	if config.Interface != "" {
		inf, err := net.InterfaceByName(config.Interface)
		if err != nil {
			return errors.New("failed to find the interface").Base(err)
		}
		isV4 := (network == "tcp4" || network == "udp4")
		if isV4 {
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], uint32(inf.Index))
			idx := *(*uint32)(unsafe.Pointer(&bytes[0]))
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, IP_UNICAST_IF, int(idx)); err != nil {
				return errors.New("failed to set IP_UNICAST_IF").Base(err)
			}
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, int(idx)); err != nil {
				return errors.New("failed to set IP_MULTICAST_IF").Base(err)
			}
		} else {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, inf.Index); err != nil {
				return errors.New("failed to set IPV6_UNICAST_IF").Base(err)
			}
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, inf.Index); err != nil {
				return errors.New("failed to set IPV6_MULTICAST_IF").Base(err)
			}
		}
	}

	if isTCPSocket(network) {
		if err := setTFO(syscall.Handle(fd), config.ParseTFOValue()); err != nil {
			return err
		}
		if config.TcpKeepAliveIdle > 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
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
				return errors.New("failed to set SO_KEEPALIVE", err)
			}
		} else if config.TcpKeepAliveIdle < 0 {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 0); err != nil {
				return errors.New("failed to unset SO_KEEPALIVE", err)
			}
		}
	}

	if config.V6Only {
		if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1); err != nil {
			return errors.New("failed to set IPV6_V6ONLY").Base(err)
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
