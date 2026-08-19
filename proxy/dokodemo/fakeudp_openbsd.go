//go:build openbsd
// +build openbsd

package dokodemo

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func FakeUDP(addr *net.UDPAddr, mark int) (net.PacketConn, error) {
	ip4 := addr.IP.To4()
	if ip4 == nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("IPv6 is not supported by the OpenBSD transparent UDP patch")}
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("socket open: %w", err)}
	}

	closeFD := true
	defer func() {
		if closeFD {
			unix.Close(fd)
		}
	}()

	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BINDANY, 1); err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option SO_BINDANY: %w", err)}
	}
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option SO_REUSEADDR: %w", err)}
	}

	sockaddr := &unix.SockaddrInet4{Port: addr.Port}
	copy(sockaddr.Addr[:], ip4)
	if err = unix.Bind(fd, sockaddr); err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("bind %s: %w", addr.String(), err)}
	}

	fdFile := os.NewFile(uintptr(fd), fmt.Sprintf("net-udp-bindany-%s", addr.String()))
	if fdFile == nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("convert descriptor to file")}
	}
	defer fdFile.Close()

	packetConn, err := net.FilePacketConn(fdFile)
	if err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("convert descriptor to packet connection: %w", err)}
	}

	closeFD = false
	return packetConn, nil
}
