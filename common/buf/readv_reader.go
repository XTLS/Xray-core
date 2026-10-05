//go:build !wasm && !openbsd
// +build !wasm,!openbsd

package buf

import (
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/features/stats"
)

type allocStrategy struct {
	current uint32
}

func (s *allocStrategy) Current() uint32 {
	return s.current
}

func (s *allocStrategy) Adjust(n uint32) {
	if n >= s.current {
		s.current *= 2
	} else {
		s.current = n
	}

	if s.current > 8 {
		s.current = 8
	}

	if s.current == 0 {
		s.current = 1
	}
}

func (s *allocStrategy) Alloc() []*Buffer {
	bs := make([]*Buffer, s.current)
	for i := range bs {
		bs[i] = New()
	}
	return bs
}

type multiReader interface {
	Init([]*Buffer)
	// Read returns -1 and no error if there is nothing to read yet.
	Read(fd uintptr) (int32, error)
	Clear()
}

// ReadVReader is a Reader that uses readv(2) syscall to read data.
type ReadVReader struct {
	io.Reader
	rawConn syscall.RawConn
	mr      multiReader
	alloc   allocStrategy
	counter stats.Counter

	// the read in progress, kept here so that a read does not allocate it
	readFn func(fd uintptr) bool
	bs     []*Buffer
	nBytes int32
	rerr   error
	ready  bool
}

// NewReadVReader creates a new ReadVReader.
func NewReadVReader(reader io.Reader, rawConn syscall.RawConn, counter stats.Counter) *ReadVReader {
	r := &ReadVReader{
		Reader:  reader,
		rawConn: rawConn,
		alloc: allocStrategy{
			current: 1,
		},
		mr:      newMultiReader(),
		counter: counter,
	}
	r.readFn = r.tryRead
	return r
}

func (r *ReadVReader) tryRead(fd uintptr) bool {
	// On Windows, the first invocation returns false to indicate "not ready"
	// to make rawConn.Read wait for readability using the runtime's own mechanism
	// because syscall.WSARecv() is a blocking call when used with nil OVERLAPPED
	if runtime.GOOS == "windows" && !r.ready {
		r.ready = true
		return false
	}

	// take the bytes right before the syscall and give them back if there is nothing to read,
	// so that they are not held while waiting for readability
	if r.bs == nil {
		r.bs = r.alloc.Alloc()
	} else {
		for _, b := range r.bs {
			*b = StackNew()
		}
	}
	r.mr.Init(r.bs)
	r.nBytes, r.rerr = r.mr.Read(fd)
	r.mr.Clear()
	if r.nBytes < 0 {
		for _, b := range r.bs {
			b.Release()
		}
		return r.rerr != nil
	}

	return true
}

func (r *ReadVReader) readMulti() (MultiBuffer, error) {
	r.ready = false
	err := r.rawConn.Read(r.readFn)
	bs, nBytes, rerr := r.bs, r.nBytes, r.rerr
	r.bs, r.rerr = nil, nil

	if err != nil {
		return nil, err
	}

	if rerr != nil {
		rerr = os.NewSyscallError("read", rerr)
		if conn, ok := r.Reader.(net.Conn); ok && conn.LocalAddr() != nil {
			rerr = &net.OpError{Op: "read", Net: conn.LocalAddr().Network(), Source: conn.LocalAddr(), Addr: conn.RemoteAddr(), Err: rerr}
		}
		return nil, rerr
	}

	if nBytes == 0 {
		ReleaseMulti(MultiBuffer(bs))
		return nil, io.EOF
	}

	nBuf := 0
	for nBuf < len(bs) {
		if nBytes <= 0 {
			break
		}
		end := nBytes
		if end > Size {
			end = Size
		}
		bs[nBuf].end = end
		nBytes -= end
		nBuf++
	}

	for i := nBuf; i < len(bs); i++ {
		bs[i].Release()
		bs[i] = nil
	}

	return MultiBuffer(bs[:nBuf]), nil
}

// ReadMultiBuffer implements Reader.
func (r *ReadVReader) ReadMultiBuffer() (MultiBuffer, error) {
	// anything else may have bytes buffered in front of rawConn,
	// and on Windows waiting for readability first costs one more syscall
	_, raw := r.Reader.(*net.TCPConn)
	if r.alloc.Current() == 1 && (!raw || runtime.GOOS == "windows") {
		b, err := ReadBuffer(r.Reader)
		if b.IsFull() {
			r.alloc.Adjust(1)
		}
		if r.counter != nil && b != nil {
			r.counter.Add(int64(b.Len()))
		}
		return MultiBuffer{b}, err
	}

	mb, err := r.readMulti()
	if r.counter != nil && mb != nil {
		r.counter.Add(int64(mb.Len()))
	}
	if err != nil {
		return nil, err
	}
	if r.alloc.Current() > 1 || mb[0].IsFull() {
		r.alloc.Adjust(uint32(len(mb)))
	}
	return mb, nil
}

var useReadv atomic.Bool

func useReadV() bool {
	return useReadv.Load()
}

func reloadEnvSettings() error {
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"
	value := platform.NewEnvFlag(platform.UseReadV).GetValue(func() string { return defaultFlagValue })
	enabled := false
	switch value {
	case defaultFlagValue, "auto", "enable":
		enabled = true
	}
	useReadv.Store(enabled)
	return nil
}

func init() {
	platform.RegisterEnvReload(reloadEnvSettings)
}
