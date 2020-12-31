// +build linux

package dokodemo

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
)

func FakeUDP(addr *net.UDPAddr, mark int) (net.PacketConn, error) {

	if addr == nil {
		addr = &net.UDPAddr{
			IP:   []byte{0, 0, 0, 0},
			Port: 0,
		}
	}

	localSocketAddress, af, err := udpAddrToSocketAddr(addr)
	if err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("build local socket address: %s", err)}
	}

	fileDescriptor, err := syscall.Socket(af, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("socket open: %s", err)}
	}

	if mark != 0 {
		if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil {
			syscall.Close(fileDescriptor)
			return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option: SO_MARK: %s", err)}
		}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option: SO_REUSEADDR: %s", err)}
	}

	if err = syscall.SetsockoptInt(fileDescriptor, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("set socket option: IP_TRANSPARENT: %s", err)}
	}

	if err = syscall.Bind(fileDescriptor, localSocketAddress); err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("socket bind: %s", err)}
	}

	fdFile := os.NewFile(uintptr(fileDescriptor), fmt.Sprintf("net-udp-fake-%s", addr.String()))
	defer fdFile.Close()

	packetConn, err := net.FilePacketConn(fdFile)
	if err != nil {
		syscall.Close(fileDescriptor)
		return nil, &net.OpError{Op: "fake", Err: fmt.Errorf("convert file descriptor to connection: %s", err)}
	}

	return packetConn, nil
}

func udpAddrToSocketAddr(addr *net.UDPAddr) (syscall.Sockaddr, int, error) {
	switch {
	case addr.IP.To4() != nil:
		ip := [4]byte{}
		copy(ip[:], addr.IP.To4())

		return &syscall.SockaddrInet4{Addr: ip, Port: addr.Port}, syscall.AF_INET, nil

	default:
		ip := [16]byte{}
		copy(ip[:], addr.IP.To16())

		zoneID, err := strconv.ParseUint(addr.Zone, 10, 32)
		if err != nil {
			return nil, 0, err
		}

		return &syscall.SockaddrInet6{Addr: ip, Port: addr.Port, ZoneId: uint32(zoneID)}, syscall.AF_INET6, nil
	}
}
