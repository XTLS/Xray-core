package net

import (
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// Destination represents a network destination including address and protocol (tcp / udp).
type Destination struct {
	Address Address
	Port    Port
	Network Network
}

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

// DestinationFromAddr generates a Destination from a net address.
func DestinationFromAddr(addr net.Addr) Destination {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return TCPDestination(IPAddress(addr.IP), Port(addr.Port))
	case *net.UDPAddr:
		return UDPDestination(IPAddress(addr.IP), Port(addr.Port))
	case *net.UnixAddr:
		return UnixDestination(DomainAddress(addr.Name))
	default:
		panic("Net: Unknown address type.")
	}
}

// ParseDestination converts a destination from its string presentation.
func ParseDestination(dest string) (Destination, error) {
	d := Destination{
		Address: AnyIP,
		Port:    Port(0),
	}
	if strings.HasPrefix(dest, "tcp:") {
		d.Network = Network_TCP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "udp:") {
		d.Network = Network_UDP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "unix:") {
		d = UnixDestination(DomainAddress(dest[5:]))
		return d, nil
	}

	hstr, pstr, err := SplitHostPort(dest)
	if err != nil {
		return d, err
	}
	if len(hstr) > 0 {
		d.Address = ParseAddress(hstr)
	}
	if len(pstr) > 0 {
		port, err := PortFromString(pstr)
		if err != nil {
			return d, err
		}
		d.Port = port
	}
	return d, nil
}

// TCPDestination creates a TCP destination with given address
func TCPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_TCP,
		Address: address,
		Port:    port,
	}
}

// UDPDestination creates a UDP destination with given address
func UDPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_UDP,
		Address: address,
		Port:    port,
	}
}

// UnixDestination creates a Unix destination with given address
func UnixDestination(address Address) Destination {
	return Destination{
		Network: Network_UNIX,
		Address: address,
	}
}

// NetAddr returns the network address in this Destination in string form.
func (d Destination) NetAddr() string {
	addr := ""
	if d.Network == Network_TCP || d.Network == Network_UDP {
		addr = d.Address.String() + ":" + d.Port.String()
	} else if d.Network == Network_UNIX {
		addr = d.Address.String()
	}
	return addr
}

// String returns the strings form of this Destination.
func (d Destination) String() string {
	prefix := "unknown:"
	switch d.Network {
	case Network_TCP:
		prefix = "tcp:"
	case Network_UDP:
		prefix = "udp:"
	case Network_UNIX:
		prefix = "unix:"
	}
	return prefix + d.NetAddr()
}

// IsValid returns true if this Destination is valid.
func (d Destination) IsValid() bool {
	return d.Network != Network_Unknown
}

// AsDestination converts current Endpoint into Destination.
func (p *Endpoint) AsDestination() Destination {
	return Destination{
		Network: p.Network,
		Address: p.Address.AsAddress(),
		Port:    Port(p.Port),
	}
}

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
