//go:build !wasm && !openbsd
// +build !wasm,!openbsd

package buf

import (
	"syscall"
	"testing"
)

type waitingRawConn struct {
	syscall.RawConn
	onWait func()
}

func (c *waitingRawConn) Read(f func(uintptr) bool) error {
	for !f(0) {
		c.onWait()
	}
	return nil
}

// notReadyReader returns its results in turn, -1 for nothing to read yet.
type notReadyReader struct {
	bs      []*Buffer
	results []int32
}

func (r *notReadyReader) Init(bs []*Buffer) { r.bs = bs }

func (r *notReadyReader) Read(uintptr) (int32, error) {
	n := r.results[0]
	r.results = r.results[1:]
	return n, nil
}

func (r *notReadyReader) Clear() {}

func TestReadVReaderNotReady(t *testing.T) {
	mr := &notReadyReader{results: []int32{-1, -1, Size + 10}}
	reader := &ReadVReader{
		rawConn: &waitingRawConn{onWait: func() {
			for _, b := range mr.bs {
				if b.v != nil {
					t.Error("a buffer is held while waiting")
				}
			}
		}},
		mr:    mr,
		alloc: allocStrategy{current: 4},
	}
	reader.readFn = reader.tryRead
	mb, err := reader.ReadMultiBuffer()
	if err != nil || len(mb) != 2 || mb.Len() != Size+10 || len(mr.results) != 0 {
		t.Fatal("buffers: ", len(mb), ", bytes: ", mb.Len(), ", error: ", err, ", reads left: ", len(mr.results))
	}
	ReleaseMulti(mb)
}
