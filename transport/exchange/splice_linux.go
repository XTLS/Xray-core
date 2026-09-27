//go:build linux

package exchange

import (
	"io"
	"net"

	"golang.org/x/sys/unix"
)

// spliceTransfer owns one nonblocking kernel pipe. Progress after each syscall
// lets normal timers and live counters remain active during kernel transfer.
func spliceTransfer(dst io.Writer, src io.Reader, onRead, onWrite func(int64)) (bool, error) {
	r, rok := src.(*net.TCPConn)
	w, wok := dst.(*net.TCPConn)
	if !rok || !wok {
		return false, nil
	}
	rr, err := r.SyscallConn()
	if err != nil {
		return false, nil
	}
	wr, err := w.SyscallConn()
	if err != nil {
		return false, nil
	}
	var pipe [2]int
	if err = unix.Pipe2(pipe[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		return false, nil
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	consumed := false
	for {
		var n int64
		var opErr error
		err = rr.Read(func(fd uintptr) bool {
			for {
				n, opErr = unix.Splice(int(fd), nil, pipe[1], nil, 64*1024, unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
				if opErr == unix.EINTR {
					continue
				}
				return opErr != unix.EAGAIN
			}
		})
		if err != nil {
			return true, err
		}
		if opErr != nil {
			if !consumed && (opErr == unix.EINVAL || opErr == unix.ENOSYS || opErr == unix.EOPNOTSUPP) {
				return false, nil
			}
			return true, opErr
		}
		if n == 0 {
			return true, io.EOF
		}
		consumed = true
		onRead(n)
		for n > 0 {
			var written int64
			err = wr.Write(func(fd uintptr) bool {
				for {
					written, opErr = unix.Splice(pipe[0], nil, int(fd), nil, int(n), unix.SPLICE_F_NONBLOCK|unix.SPLICE_F_MOVE)
					if opErr == unix.EINTR {
						continue
					}
					return opErr != unix.EAGAIN
				}
			})
			if written > 0 {
				n -= written
				onWrite(written)
			}
			if err != nil {
				return true, err
			}
			if opErr != nil {
				return true, opErr
			}
			if written == 0 {
				return true, io.ErrShortWrite
			}
		}
	}
}
