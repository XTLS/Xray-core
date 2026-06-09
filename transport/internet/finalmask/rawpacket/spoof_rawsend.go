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
	mu       sync.Mutex
	closed   bool
}

func openRawSender(dstIP netip.Addr) (*rawSendFD, error) {
	if !dstIP.Is4() {
		return nil, fmt.Errorf("rawpacket: IPv6 raw sender not yet supported")
	}

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

	sa := &unix.SockaddrInet4{}
	sa.Addr = dstIP.As4()
	return &rawSendFD{fd: fd, sockAddr: sa}, nil
}

func (r *rawSendFD) send(packet []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fmt.Errorf("rawpacket: raw sender closed")
	}
	return unix.Sendto(r.fd, packet, 0, r.sockAddr)
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
