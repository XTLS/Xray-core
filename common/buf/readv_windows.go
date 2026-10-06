package buf

import (
	"syscall"
)

type windowsReader struct {
	bufs  []syscall.WSABuf
	ready bool
}

func (r *windowsReader) Init(bs []*Buffer) {
	if r.bufs == nil {
		r.bufs = make([]syscall.WSABuf, 0, len(bs))
	}
	for _, b := range bs {
		r.bufs = append(r.bufs, syscall.WSABuf{Len: uint32(Size), Buf: &b.v[0]})
	}
	r.ready = false
}

func (r *windowsReader) Clear() {
	for idx := range r.bufs {
		r.bufs[idx].Buf = nil
	}
	r.bufs = r.bufs[:0]
}

func (r *windowsReader) Read(fd uintptr) (int32, error) {
	// On the first invocation, we return -1 to indicate "not ready"
	// to make rawConn.Read wait for readability using the runtime's own mechanism
	// because syscall.WSARecv() is a blocking call when used with nil OVERLAPPED
	if !r.ready {
		r.ready = true
		return -1, nil
	}

	var nBytes uint32
	var flags uint32
	err := syscall.WSARecv(syscall.Handle(fd), &r.bufs[0], uint32(len(r.bufs)), &nBytes, &flags, nil, nil)
	if err != nil {
		// rawConn.Read returns it when it waits for readability again
		return -1, nil
	}
	return int32(nBytes), nil
}

func newMultiReader() multiReader {
	return new(windowsReader)
}
