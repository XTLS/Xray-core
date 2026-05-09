package rawpacket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const PlatformSupported = true

// FreeBSD tcp_info offsets for snd_nxt and rcv_nxt.
// Derived from FreeBSD sys/netinet/tcp.h struct tcp_info layout.
//
// struct tcp_info {
//     u8 state, __ca, __retrans, __probes, __backoff, opts, wscale  = 8 bytes (with pad)
//     u32 rto, __ato, snd_mss, rcv_mss                             = 16 bytes (offset 8)
//     u32 __unacked, __sacked, __lost, __retrans, __fackets         = 20 bytes (offset 24)
//     u32 __last_data_sent, __last_ack_sent, last_data_recv, __last_ack_recv = 16 bytes (offset 44)
//     u32 __pmtu, __rcv_ssthresh, rtt, rttvar, snd_ssthresh, snd_cwnd, __advmss, __reordering = 32 bytes (offset 60)
//     u32 __rcv_rtt, rcv_space                                     = 8 bytes  (offset 92)
//     u32 snd_wnd, snd_bwnd                                        = 8 bytes  (offset 100)
//     u32 snd_nxt, rcv_nxt                                         = 8 bytes  (offset 108)
//     ... remaining fields
// }
const (
	freebsdTCPInfoSndNxtOffset = 108
	freebsdTCPInfoRcvNxtOffset = 112
	freebsdTCPInfoMinSize      = 116 // must read at least through rcv_nxt
)

type freebsdSpoofer struct {
	method      Method
	src         netip.AddrPort
	dst         netip.AddrPort
	rawFD       int
	rawSockAddr unix.Sockaddr
	sendNext    uint32
	receiveNext uint32
	ttl         uint8
}

func newRawSpoofer(conn net.Conn, method Method, ttl uint8) (rawSpoofer, error) {
	if method == MethodWrongTimestamp {
		return nil, errors.New("rawpacket: wrong-timestamp is not supported on FreeBSD")
	}
	tcpConn, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	fd, sockaddr, err := openFreeBSDRawSocket(src, dst)
	if err != nil {
		return nil, err
	}
	sendNext, receiveNext, err := readFreeBSDTCPSequence(tcpConn)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &freebsdSpoofer{
		method:      method,
		src:         src,
		dst:         dst,
		rawFD:       fd,
		rawSockAddr: sockaddr,
		sendNext:    sendNext,
		receiveNext: receiveNext,
		ttl:         ttl,
	}, nil
}

// readFreeBSDTCPSequence retrieves snd_nxt and rcv_nxt via TCP_INFO getsockopt.
func readFreeBSDTCPSequence(conn *net.TCPConn) (uint32, uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("rawpacket: SyscallConn: %w", err)
	}
	var sendNext, receiveNext uint32
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		buf := make([]byte, 256) // generous buffer for tcp_info
		bufLen := uint32(len(buf))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			uintptr(syscall.IPPROTO_TCP),
			uintptr(0x20), // TCP_INFO = 0x20
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&bufLen)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("rawpacket: getsockopt TCP_INFO: %w", errno)
			return
		}
		if bufLen < freebsdTCPInfoMinSize {
			sockErr = fmt.Errorf("rawpacket: TCP_INFO too short: %d < %d", bufLen, freebsdTCPInfoMinSize)
			return
		}
		sendNext = binary.NativeEndian.Uint32(buf[freebsdTCPInfoSndNxtOffset : freebsdTCPInfoSndNxtOffset+4])
		receiveNext = binary.NativeEndian.Uint32(buf[freebsdTCPInfoRcvNxtOffset : freebsdTCPInfoRcvNxtOffset+4])
	})
	if err != nil {
		return 0, 0, err
	}
	if sockErr != nil {
		return 0, 0, sockErr
	}
	return sendNext, receiveNext, nil
}

func openFreeBSDRawSocket(src, dst netip.AddrPort) (int, unix.Sockaddr, error) {
	if dst.Addr().Is4() {
		return openIPv4RawSocket(dst)
	}
	// FreeBSD, like macOS, does not support IPV6_HDRINCL on SOCK_RAW/IPPROTO_TCP.
	// The kernel constructs the IPv6 header. Bind to the source address
	// and let the kernel fill in the IPv6 header automatically.
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, fmt.Errorf("rawpacket: open AF_INET6 SOCK_RAW: %w", err)
	}
	err = unix.Bind(fd, &unix.SockaddrInet6{Addr: src.Addr().As16()})
	if err != nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("rawpacket: bind AF_INET6 SOCK_RAW: %w", err)
	}
	sockaddr := &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()}
	return fd, sockaddr, nil
}

func (s *freebsdSpoofer) Inject(payload []byte) error {
	if !s.src.Addr().Is4() {
		// IPv6: kernel builds the IP header, we supply TCP segment only.
		segment, err := buildSpoofTCPSegment(s.method, s.src, s.dst, s.sendNext, s.receiveNext, 0, payload)
		if err != nil {
			return err
		}
		err = unix.Sendto(s.rawFD, segment, 0, s.rawSockAddr)
		if err != nil {
			return fmt.Errorf("rawpacket: sendto raw socket: %w", err)
		}
		return nil
	}
	// IPv4: we build the full IP+TCP frame with IP_HDRINCL.
	frame, err := buildSpoofFrame(s.method, s.src, s.dst, s.sendNext, s.receiveNext, 0, nil, payload, s.ttl)
	if err != nil {
		return err
	}
	// FreeBSD inherits the historical BSD quirk: with IP_HDRINCL the kernel
	// expects ip_len and ip_off in host byte order, not network byte order.
	ip := IPv4(frame)
	binary.NativeEndian.PutUint16(ip[2:4], ip.TotalLength())
	binary.NativeEndian.PutUint16(ip[6:8], uint16(ip.Flags())<<13|ip.FragmentOffset())
	err = unix.Sendto(s.rawFD, frame, 0, s.rawSockAddr)
	if err != nil {
		return fmt.Errorf("rawpacket: sendto raw socket: %w", err)
	}
	return nil
}

func (s *freebsdSpoofer) Close() error {
	if s.rawFD < 0 {
		return nil
	}
	err := unix.Close(s.rawFD)
	s.rawFD = -1
	return err
}
