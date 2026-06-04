package rawpacket

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

const PlatformSupported = true

const (
	// Values of enum { TCP_NO_QUEUE, TCP_RECV_QUEUE, TCP_SEND_QUEUE } from
	// include/net/tcp.h; not exported by golang.org/x/sys/unix.
	tcpRecvQueue = 1
	tcpSendQueue = 2
)

type linuxSpoofer struct {
	method      Method
	src         netip.AddrPort
	dst         netip.AddrPort
	rawFD       int
	rawSockAddr unix.Sockaddr
	sendNext    uint32
	receiveNext uint32
	timestamp   uint32
	ttl         uint8
}

func newRawSpoofer(conn net.Conn, method Method, ttl uint8) (rawSpoofer, error) {
	tcpConn, src, dst, err := tcpEndpoints(conn)
	if err != nil {
		return nil, err
	}
	fd, sockaddr, err := openLinuxRawSocket(dst)
	if err != nil {
		return nil, err
	}
	spoofer := &linuxSpoofer{
		method:      method,
		src:         src,
		dst:         dst,
		rawFD:       fd,
		rawSockAddr: sockaddr,
		ttl:         ttl,
	}
	err = spoofer.loadSequenceNumbers(tcpConn)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return spoofer, nil
}

func openLinuxRawSocket(dst netip.AddrPort) (int, unix.Sockaddr, error) {
	if dst.Addr().Is4() {
		return openIPv4RawSocket(dst)
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return -1, nil, fmt.Errorf("open AF_INET6 SOCK_RAW: %w", err)
	}
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
	if err != nil {
		unix.Close(fd)
		return -1, nil, fmt.Errorf("set IPV6_HDRINCL: %w", err)
	}
	// Linux raw IPv6 sockets interpret sin6_port as a nexthdr protocol number
	// (see raw(7)); any value other than 0 or the socket's IPPROTO_TCP causes
	// sendto to fail with EINVAL. The destination is already encoded in the
	// user-supplied IPv6 header under IPV6_HDRINCL.
	sockaddr := &unix.SockaddrInet6{Addr: dst.Addr().As16()}
	return fd, sockaddr, nil
}

// loadSequenceNumbers briefly enters TCP_REPAIR mode to read snd_nxt and
// rcv_nxt from the kernel, then immediately exits TCP_REPAIR. TCP_REPAIR
// requires CAP_NET_ADMIN.
func (s *linuxSpoofer) loadSequenceNumbers(tcpConn *net.TCPConn) error {
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}
	var ctrlErr error
	err = rawConn.Control(func(raw uintptr) {
		fd := int(raw)

		timestamp, tsErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_TIMESTAMP)
		if tsErr == nil {
			s.timestamp = uint32(timestamp)
		}

		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_ON)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("rawpacket: enter TCP_REPAIR (need CAP_NET_ADMIN): %w", ctrlErr)
			return
		}
		defer func() {
			offErr := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR, unix.TCP_REPAIR_OFF)
			if offErr != nil {
				offErr = fmt.Errorf("rawpacket: leave TCP_REPAIR: %w", offErr)
				if ctrlErr == nil {
					ctrlErr = offErr
				} else {
					ctrlErr = fmt.Errorf("%v; also %w", ctrlErr, offErr)
				}
			}
		}()

		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpSendQueue)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("rawpacket: select TCP_SEND_QUEUE: %w", ctrlErr)
			return
		}
		sendSequence, seqErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if seqErr != nil {
			ctrlErr = fmt.Errorf("rawpacket: read send queue sequence: %w", seqErr)
			return
		}
		ctrlErr = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_REPAIR_QUEUE, tcpRecvQueue)
		if ctrlErr != nil {
			ctrlErr = fmt.Errorf("rawpacket: select TCP_RECV_QUEUE: %w", ctrlErr)
			return
		}
		receiveSequence, seqErr := unix.GetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUEUE_SEQ)
		if seqErr != nil {
			ctrlErr = fmt.Errorf("rawpacket: read recv queue sequence: %w", seqErr)
			return
		}
		s.sendNext = uint32(sendSequence)
		s.receiveNext = uint32(receiveSequence)
	})
	if err != nil {
		return err
	}
	return ctrlErr
}

func (s *linuxSpoofer) Inject(payload []byte) error {
	frame, err := buildSpoofFrame(s.method, s.src, s.dst, s.sendNext, s.receiveNext, s.timestamp, nil, payload, s.ttl)
	if err != nil {
		return err
	}
	// Use a non-zero IP ID. The buildSpoofFrame → buildTCPSegment path
	// passes id=0 to IPv4.Encode; override it with a random value since
	// IP ID 0 is a DPI red flag.
	if s.src.Addr().Is4() && len(frame) >= IPv4MinimumSize {
		ip := IPv4(frame)
		ip.SetID(uint16(rand.Uint32()))
		ip.RecalcChecksum()
	}
	err = unix.Sendto(s.rawFD, frame, 0, s.rawSockAddr)
	if err != nil {
		return fmt.Errorf("sendto raw socket: %w", err)
	}
	return nil
}

func (s *linuxSpoofer) Close() error {
	if s.rawFD < 0 {
		return nil
	}
	err := unix.Close(s.rawFD)
	s.rawFD = -1
	return err
}
