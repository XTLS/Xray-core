//go:build !windows

package icmp

import (
	stdnet "net"
	"os"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
)

func listenEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
	if IsDatagramNetwork(config.network) {
		return listenDatagramEchoSocket(config)
	}
	return listenRawEchoSocket(config)
}

func listenDatagramEchoSocket(config socketConfig) (stdnet.PacketConn, error) {
	family := syscall.AF_INET
	proto := syscall.IPPROTO_ICMP
	var sa syscall.Sockaddr = &syscall.SockaddrInet4{}

	switch config.network {
	case "udp4":
	case "udp6":
		family = syscall.AF_INET6
		proto = syscall.IPPROTO_ICMPV6
		sa = &syscall.SockaddrInet6{}
	default:
		return nil, errors.New("unsupported datagram icmp network: ", config.network)
	}

	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, os.NewSyscallError("bind", err)
	}

	file := os.NewFile(uintptr(fd), "icmp datagram")
	conn, err := stdnet.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("icmp datagram conn does not expose syscall conn")
	}

	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := applyRawSocketControllers(config.controllerNetwork, config.remoteAddr.String(), rawConn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
