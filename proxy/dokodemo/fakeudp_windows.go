//go:build windows
// +build windows

package dokodemo

import (
	"net"
	"syscall"
)

func FakeUDP(addr *net.UDPAddr, mark int) (net.PacketConn, error) {
	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return udpConn, err
	}
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	err = rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}
