package buf

import (
	"syscall"
)

type windowsReader struct {
	bufs []syscall.WSABuf
	// primed tracks whether readability has been awaited for the current
	// multi-buffer read. Go runtime network sockets on Windows are kept in
	// blocking mode at the Winsock level (the runtime simulates non-blocking
	// I/O with overlapped operations), so a raw WSARecv without an OVERLAPPED
	// blocks its OS thread when no data is available and cannot be aborted by
	// Close, leaving the socket open (no FIN). Instead, the first call returns
	// -1 so RawConn.Read waits for readability with its own interruptible
	// overlapped read; only then is the real WSARecv issued, which returns
	// immediately because data (or EOF) is available.
	primed bool
}

func (r *windowsReader) Init(bs []*Buffer) {
	if r.bufs == nil {
		r.bufs = make([]syscall.WSABuf, 0, len(bs))
	}
	for _, b := range bs {
		r.bufs = append(r.bufs, syscall.WSABuf{Len: uint32(Size), Buf: &b.v[0]})
	}
	r.primed = false
}

func (r *windowsReader) Clear() {
	for idx := range r.bufs {
		r.bufs[idx].Buf = nil
	}
	r.bufs = r.bufs[:0]
}

func (r *windowsReader) Read(fd uintptr) int32 {
	if !r.primed {
		r.primed = true
		return -1
	}
	var nBytes uint32
	var flags uint32
	err := syscall.WSARecv(syscall.Handle(fd), &r.bufs[0], uint32(len(r.bufs)), &nBytes, &flags, nil, nil)
	if err != nil {
		return -1
	}
	return int32(nBytes)
}

func newMultiReader() multiReader {
	return new(windowsReader)
}
