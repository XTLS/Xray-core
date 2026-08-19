//go:build darwin || freebsd || linux

package rawpacket

import (
	"fmt"
	"net/netip"
	"sync"

	"golang.org/x/sys/unix"
)

type rawSendFD struct {
	fd       int
	sockAddr unix.Sockaddr
	// sendFn, when set, replaces the real send path (used by tests).
	sendFn func(pkt []byte, dstIP netip.Addr) error
	mu     sync.Mutex
	closed bool
}

func openRawSender(dstIP netip.Addr) (*rawSendFD, error) {
	if !dstIP.Is4() {
		return nil, fmt.Errorf("rawpacket: IPv6 raw sender not yet supported")
	}

	fd, err := openRawSenderAny()
	if err != nil {
		return nil, err
	}
	sa := &unix.SockaddrInet4{}
	sa.Addr = dstIP.As4()
	fd.sockAddr = sa
	return fd, nil
}

// openRawSenderAny opens a raw sending socket without binding it to a
// fixed destination. Used by the masquerade responder, which must send
// to arbitrary probe addresses.
func openRawSenderAny() (*rawSendFD, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("rawpacket: open SOCK_RAW: %w", err)
	}
	err = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("rawpacket: set IP_HDRINCL: %w", err)
	}

	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4*1024*1024)
	return &rawSendFD{fd: fd}, nil
}

func (r *rawSendFD) send(packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("rawpacket: raw sender closed")
	}
	if r.sockAddr == nil {
		return fmt.Errorf("rawpacket: raw sender has no destination")
	}
	return unix.Sendto(r.fd, packet, 0, r.sockAddr)
}

// sendTo sends packet to dstIP, building the socket address per call.
func (r *rawSendFD) sendTo(packet []byte, dstIP netip.Addr) error {
	if r.sendFn != nil {
		return r.sendFn(packet, dstIP)
	}
	if !dstIP.Is4() {
		return fmt.Errorf("rawpacket: IPv6 raw sender not yet supported")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("rawpacket: raw sender closed")
	}
	sa := &unix.SockaddrInet4{}
	sa.Addr = dstIP.As4()
	return unix.Sendto(r.fd, packet, 0, sa)
}

func (r *rawSendFD) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return unix.Close(r.fd)
}
