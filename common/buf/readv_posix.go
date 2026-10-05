//go:build !windows && !wasm && !illumos && !openbsd
// +build !windows,!wasm,!illumos,!openbsd

package buf

import (
	"syscall"
	"unsafe"
)

type posixReader struct {
	iovecs []syscall.Iovec
}

func (r *posixReader) Init(bs []*Buffer) {
	iovecs := r.iovecs
	if iovecs == nil {
		iovecs = make([]syscall.Iovec, 0, len(bs))
	}
	for idx, b := range bs {
		iovecs = append(iovecs, syscall.Iovec{
			Base: &b.v[0],
		})
		iovecs[idx].SetLen(int(Size))
	}
	r.iovecs = iovecs
}

func (r *posixReader) Read(fd uintptr) (int32, error) {
	for {
		var n uintptr
		var e syscall.Errno
		if len(r.iovecs) == 1 {
			// read(2) is cheaper than readv(2)
			n, _, e = syscall.Syscall(syscall.SYS_READ, fd, uintptr(unsafe.Pointer(r.iovecs[0].Base)), uintptr(Size))
		} else {
			n, _, e = syscall.Syscall(syscall.SYS_READV, fd, uintptr(unsafe.Pointer(&r.iovecs[0])), uintptr(len(r.iovecs)))
		}
		switch e {
		case 0:
			return int32(n), nil
		case syscall.EINTR:
		case syscall.EAGAIN:
			return -1, nil
		default:
			return -1, e
		}
	}
}

func (r *posixReader) Clear() {
	for idx := range r.iovecs {
		r.iovecs[idx].Base = nil
	}
	r.iovecs = r.iovecs[:0]
}

func newMultiReader() multiReader {
	return &posixReader{}
}
