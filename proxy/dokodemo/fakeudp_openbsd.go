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
	domain := unix.AF_INET6
	var sockaddr unix.Sockaddr
	if ip4 := addr.IP.To4(); ip4 != nil {
		domain = unix.AF_INET
		sa := &unix.SockaddrInet4{Port: addr.Port}
		copy(sa.Addr[:], ip4)
		sockaddr = sa
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		sa := &unix.SockaddrInet6{Port: addr.Port}
		copy(sa.Addr[:], ip6)
		if addr.Zone != "" {
			iface, err := net.InterfaceByName(addr.Zone)
			if err != nil {
				return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("resolve zone %s: %w", addr.Zone, err)}
			}
			sa.ZoneId = uint32(iface.Index)
		}
		sockaddr = sa
	} else {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("unsupported address %v", addr.IP)}
	}

	fd, err := unix.Socket(domain, unix.SOCK_DGRAM, 0)
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
	// Several client sessions can be answered from the same original
	// destination at the same time, so the address has to be shareable.
	if err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option SO_REUSEPORT: %w", err)}
	}

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
