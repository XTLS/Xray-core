package splithttp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// scriptedReader has reads[0] bytes ready for the next Read, and returns the
// last read together with io.EOF.
type scriptedReader struct {
	data  []byte
	reads []int
}

func (r *scriptedReader) Read(p []byte) (int, error) {
	n := copy(p, r.data[:r.reads[0]])
	r.data, r.reads = r.data[n:], r.reads[1:]
	if len(r.reads) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestSplitConnReadMultiBuffer(t *testing.T) {
	steps := []struct {
		ready, read int
		bulk        bool
	}{
		{100, 100, false},
		{8192, 8192, true}, // a full 8 KiB read switches to 32 KiB reads
		{50000, 32768, true},
		{24576, 24576, true},
		{8192, 8192, false}, // one that fits into a Buffer switches back
		{9000, 8192, true},
		{300, 300, false},
	}
	data := make([]byte, 100000)
	rand.Read(data)
	r := &scriptedReader{data: data}
	for _, s := range steps {
		r.reads = append(r.reads, s.ready)
	}
	c := &splitConn{reader: io.NopCloser(r)}

	var got []byte
	for i, s := range steps {
		mb, err := c.ReadMultiBuffer()
		if (err == io.EOF) != (i == len(steps)-1) {
			t.Fatal("step ", i, ": ", err)
		}
		if mb.Len() != int32(s.read) || c.bulk != s.bulk {
			t.Fatal("step ", i, ": read ", mb.Len(), ", bulk ", c.bulk)
		}
		for _, b := range mb {
			if b.Len() > buf.Size {
				t.Fatal("step ", i, ": buffer of ", b.Len())
			}
			got = append(got, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
	}
	if !bytes.Equal(got, data[:len(got)]) {
		t.Fatal("data mismatch")
	}
}
