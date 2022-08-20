//go:build darwin

package net

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	PfOut       = 2
	IOCOut      = 0x40000000
	IOCIn       = 0x80000000
	IOCInOut    = IOCIn | IOCOut
	IOCPARMMask = 0x1FFF
	LEN         = 4*16 + 4*4 + 4*1
	// #define	_IOC(inout,group,num,len) (inout | ((len & IOCPARMMask) << 16) | ((group) << 8) | (num))
	// #define	_IOWR(g,n,t)	_IOC(IOCInOut,	(g), (n), sizeof(t))
	// #define DIOCNATLOOK		_IOWR('D', 23, struct pfioc_natlook)
	DIOCNATLOOK = IOCInOut | ((LEN & IOCPARMMask) << 16) | ('D' << 8) | 23
)

// OriginalDst uses ioctl to read original destination from /dev/pf
func OriginalDst(conn Conn) (Destination, error) {
	f, err := os.Open("/dev/pf")
	if err != nil {
		return Destination{}, newError("failed to open device /dev/pf").Base(err)
	}
	defer f.Close()

	fd := f.Fd()
	nl := struct { // struct pfioc_natlook
		saddr, daddr, rsaddr, rdaddr       [16]byte
		sxport, dxport, rsxport, rdxport   [4]byte
		af, proto, protoVariant, direction uint8
	}{
		af:        syscall.AF_INET,
		proto:     syscall.IPPROTO_TCP,
		direction: PfOut,
	}
	var raIP, laIP net.IP
	var raPort, laPort int
	la := conn.LocalAddr()
	ra := conn.RemoteAddr()
	switch la.(type) {
	case *net.TCPAddr:
		raIP = ra.(*net.TCPAddr).IP
		laIP = la.(*net.TCPAddr).IP
		raPort = ra.(*net.TCPAddr).Port
		laPort = la.(*net.TCPAddr).Port
	case *net.UDPAddr:
		raIP = ra.(*net.UDPAddr).IP
		laIP = la.(*net.UDPAddr).IP
		raPort = ra.(*net.UDPAddr).Port
		laPort = la.(*net.UDPAddr).Port
	}
	if raIP.To4() != nil {
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("127.0.0.1")
		}
		copy(nl.saddr[:net.IPv4len], raIP.To4())
		copy(nl.daddr[:net.IPv4len], laIP.To4())
	}
	if raIP.To16() != nil && raIP.To4() == nil {
		if laIP.IsUnspecified() {
			laIP = net.ParseIP("::1")
		}
		copy(nl.saddr[:], raIP)
		copy(nl.daddr[:], laIP)
	}
	nl.sxport[0], nl.sxport[1] = byte(raPort>>8), byte(raPort)
	nl.dxport[0], nl.dxport[1] = byte(laPort>>8), byte(laPort)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, DIOCNATLOOK, uintptr(unsafe.Pointer(&nl))); errno != 0 {
		return Destination{}, os.NewSyscallError("ioctl", err)
	}

	odPort := nl.rdxport
	var odIP net.IP
	switch nl.af {
	case syscall.AF_INET:
		odIP = make(net.IP, net.IPv4len)
		copy(odIP, nl.rdaddr[:net.IPv4len])
	case syscall.AF_INET6:
		odIP = make(net.IP, net.IPv6len)
		copy(odIP, nl.rdaddr[:])
	}
	return Destination{
		Address: IPAddress(odIP),
		Port:    PortFromBytes(odPort[:2]),
		Network: Network_TCP,
	}, nil
}
