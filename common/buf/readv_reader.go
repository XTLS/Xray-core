//go:build !openbsd

package buf

import (
	"io"
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
	Read(fd uintptr) int32
	Clear()
}

// ReadVReader is a Reader that uses readv(2) syscall to read data.
// Use it by pointer from NewReadVReader: a copy reads into the original.
type ReadVReader struct {
	io.Reader
	rawConn syscall.RawConn
	mr      multiReader
	alloc   allocStrategy
	counter stats.Counter

	// read is r.readFD, bound once: a method value passed to rawConn.Read allocates per call.
	read   func(fd uintptr) bool
	nBytes int32
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
	r.read = r.readFD
	return r
}

// readFD reads into the buffers of r.mr; a negative count makes rawConn.Read wait and retry.
func (r *ReadVReader) readFD(fd uintptr) bool {
	r.nBytes = r.mr.Read(fd)
	return r.nBytes >= 0
}

func (r *ReadVReader) readMulti() (MultiBuffer, error) {
	bs := r.alloc.Alloc()

	r.mr.Init(bs)
	r.nBytes = 0
	err := r.rawConn.Read(r.read)
	r.mr.Clear()
	nBytes := r.nBytes

	if err != nil {
		ReleaseMulti(MultiBuffer(bs))
		return nil, err
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
	if r.alloc.Current() == 1 {
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
	r.alloc.Adjust(uint32(len(mb)))
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
