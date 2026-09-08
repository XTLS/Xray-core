package tlsspoof

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

const PlatformSupported = true

// Offsets into xinpcb_n within each net.inet.tcp.pcblist_n record, identical
// to the values used by common/process/searcher_darwin_shared.go.
const (
	darwinXinpgenSize       = 24
	darwinXsocketOffset     = 104
	darwinXinpcbForeignPort = 16
	darwinXinpcbLocalPort   = 18
	darwinXinpcbVFlag       = 44
	darwinXinpcbForeignAddr = 48
	darwinXinpcbLocalAddr   = 64
	darwinXinpcbIPv4Offset  = 12

	darwinTCPExtraSize = 208

	darwinXtcpcbSndNxtOffset = 56
	darwinXtcpcbRcvNxtOffset = 80
)

// darwinStructSize returns the size of xinpcb_n for the running Darwin kernel.
// Darwin 22 (macOS 13 Ventura) grew the struct from 384 to 408 bytes; there is
// no ABI-stable way to read it, so we key off the kernel version.
var darwinStructSize = sync.OnceValues(func() (int, error) {
	value, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return 0, func(err error, m string) error { return err }(err, "sysctl kern.osrelease")
	}
	major, _, ok := strings.Cut(value, ".")
	if !ok {
		return 0, fmt.Errorf("unexpected kern.osrelease format: %s", value)
	}
	n, err := strconv.ParseInt(major, 10, 64)
	if err != nil {
		return 0, func(err error, m string) error { return err }(err, "parse kern.osrelease major version: ")
	}
	if n >= 22 {
		return 408, nil
	}
	return 384, nil
})

type darwinSpoofer struct {
	method      Method
	src         netip.AddrPort
	dst         netip.AddrPort
	rawFD       int
	rawSockAddr unix.Sockaddr
	sendNext    uint32
	receiveNext uint32
}

func newRawSpoofer(conn net.Conn, method Method) (rawSpoofer, error) {
	if method == MethodWrongTimestamp {
		return nil, errors.New("tls_spoof: wrong-timestamp is not supported on macOS")
	}
	_, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	fd, sockaddr, err := openDarwinRawSocket(src, dst)
	if err != nil {
		return nil, err
	}
	sendNext, receiveNext, err := readDarwinTCPSequence(src, dst)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &darwinSpoofer{
		method:      method,
		src:         src,
		dst:         dst,
		rawFD:       fd,
		rawSockAddr: sockaddr,
		sendNext:    sendNext,
		receiveNext: receiveNext,
	}, nil
}

// readDarwinTCPSequence scans net.inet.tcp.pcblist_n for the PCB that matches
// src -> dst and returns (snd_nxt, rcv_nxt). These live in xtcpcb_n at the end
// of each record; see darwin-xnu bsd/netinet/in_pcblist.c:get_pcblist_n.
func readDarwinTCPSequence(src, dst netip.AddrPort) (uint32, uint32, error) {
	buffer, err := unix.SysctlRaw("net.inet.tcp.pcblist_n")
	if err != nil {
		return 0, 0, func(err error, m string) error { return err }(err, "sysctl net.inet.tcp.pcblist_n")
	}
	structSize, err := darwinStructSize()
	if err != nil {
		return 0, 0, err
	}
	itemSize := structSize + darwinTCPExtraSize
	for i := darwinXinpgenSize; i+itemSize <= len(buffer); i += itemSize {
		inpcb := buffer[i : i+darwinXsocketOffset]
		xtcpcb := buffer[i+structSize : i+itemSize]
		localPort := binary.BigEndian.Uint16(inpcb[darwinXinpcbLocalPort : darwinXinpcbLocalPort+2])
		remotePort := binary.BigEndian.Uint16(inpcb[darwinXinpcbForeignPort : darwinXinpcbForeignPort+2])
		if localPort != src.Port() || remotePort != dst.Port() {
			continue
		}
		versionFlag := inpcb[darwinXinpcbVFlag]
		var localAddr, remoteAddr netip.Addr
		switch {
		case versionFlag&0x1 != 0:
			localAddr = netip.AddrFrom4([4]byte(inpcb[darwinXinpcbLocalAddr+darwinXinpcbIPv4Offset : darwinXinpcbLocalAddr+darwinXinpcbIPv4Offset+4]))
			remoteAddr = netip.AddrFrom4([4]byte(inpcb[darwinXinpcbForeignAddr+darwinXinpcbIPv4Offset : darwinXinpcbForeignAddr+darwinXinpcbIPv4Offset+4]))
		case versionFlag&0x2 != 0:
			localAddr = netip.AddrFrom16([16]byte(inpcb[darwinXinpcbLocalAddr : darwinXinpcbLocalAddr+16]))
			remoteAddr = netip.AddrFrom16([16]byte(inpcb[darwinXinpcbForeignAddr : darwinXinpcbForeignAddr+16]))
		default:
			continue
		}
		if localAddr.Unmap() != src.Addr() || remoteAddr.Unmap() != dst.Addr() {
			continue
		}
		sendNext := binary.NativeEndian.Uint32(xtcpcb[darwinXtcpcbSndNxtOffset : darwinXtcpcbSndNxtOffset+4])
		receiveNext := binary.NativeEndian.Uint32(xtcpcb[darwinXtcpcbRcvNxtOffset : darwinXtcpcbRcvNxtOffset+4])
		return sendNext, receiveNext, nil
	}
	return 0, 0, fmt.Errorf("tls_spoof: connection %v->%v not found in pcblist_n", src, dst)
}

func openDarwinRawSocket(src, dst netip.AddrPort) (int, unix.Sockaddr, error) {
	if dst.Addr().Is4() {
		return openIPv4RawSocket(dst)
	}
	// macOS does not accept IPV6_HDRINCL on AF_INET6 SOCK_RAW IPPROTO_TCP
	// sockets, so the kernel builds the IPv6 header itself. Bind to the real
	// connection's source address so in6_selectsrc returns it, and rely on
	// in6p_cksum defaulting to -1 so the user-supplied TCP checksum is
	// preserved (including deliberately corrupted ones).
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, func(err error, m string) error { return err }(err, "open AF_INET6 SOCK_RAW")
	}
	err = unix.Bind(fd, &unix.SockaddrInet6{Addr: src.Addr().As16()})
	if err != nil {
		unix.Close(fd)
		return -1, nil, func(err error, m string) error { return err }(err, "bind AF_INET6 SOCK_RAW")
	}
	sockaddr := &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()}
	return fd, sockaddr, nil
}

func (s *darwinSpoofer) Inject(payload []byte) error {
	if !s.src.Addr().Is4() {
		segment, err := buildSpoofTCPSegment(s.method, s.src, s.dst, s.sendNext, s.receiveNext, 0, payload)
		if err != nil {
			return err
		}
		err = unix.Sendto(s.rawFD, segment, 0, s.rawSockAddr)
		if err != nil {
			return func(err error, m string) error { return err }(err, "sendto raw socket")
		}
		return nil
	}
	frame, err := buildSpoofFrame(s.method, s.src, s.dst, s.sendNext, s.receiveNext, 0, nil, payload)
	if err != nil {
		return err
	}
	// Darwin inherits the historical BSD quirk: with IP_HDRINCL the kernel
	// expects ip_len and ip_off in host byte order, not network byte order.
	ip := IPv4(frame)
	binary.NativeEndian.PutUint16(ip[2:4], ip.TotalLength())
	binary.NativeEndian.PutUint16(ip[6:8], uint16(ip.Flags())<<13|ip.FragmentOffset())
	err = unix.Sendto(s.rawFD, frame, 0, s.rawSockAddr)
	if err != nil {
		return func(err error, m string) error { return err }(err, "sendto raw socket")
	}
	return nil
}

func (s *darwinSpoofer) Close() error {
	if s.rawFD < 0 {
		return nil
	}
	err := unix.Close(s.rawFD)
	s.rawFD = -1
	return err
}
