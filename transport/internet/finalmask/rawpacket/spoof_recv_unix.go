//go:build darwin || freebsd || linux

package rawpacket

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

type rawRecvSocket struct {
	fd         int
	buf        []byte
	closedFlag bool
	proto      uint8
}

func newRawRecvSocket(proto uint8, bufSize int) (*rawRecvSocket, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("rawpacket: socket: %w", err)
	}
	if bufSize > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize)
	}
	// 1-second timeout for clean shutdown
	tv := unix.Timeval{Sec: 1, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	// Linux only: attach a classic-BPF filter so the kernel drops
	// non-matching protocol traffic before userspace sees it.
	if runtime.GOOS == "linux" {
		attachBPFFilter(fd, proto)
	}
	return &rawRecvSocket{fd: fd, buf: make([]byte, 65536), proto: proto}, nil
}

func (r *rawRecvSocket) recv() ([]byte, bool) {
	if r.closedFlag {
		return nil, false
	}
	n, _, err := unix.Recvfrom(r.fd, r.buf, 0)
	if err != nil {
		return nil, false
	}
	if n == 0 {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, r.buf[:n])
	return out, true
}

func (r *rawRecvSocket) closed() bool {
	return r.closedFlag
}

func (r *rawRecvSocket) close() {
	if !r.closedFlag {
		r.closedFlag = true
		unix.Close(r.fd)
	}
}
