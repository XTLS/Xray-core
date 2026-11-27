//go:build !windows && !openbsd

package buf

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common"
)

func TestReadVReaderReadMultiAllocs(t *testing.T) {
	pr, pw, err := os.Pipe()
	common.Must(err)
	defer pr.Close()
	defer pw.Close()
	rawConn, err := pr.SyscallConn()
	common.Must(err)

	reader := NewReadVReader(pr, rawConn, nil)
	data := make([]byte, 2*Size)
	n := testing.AllocsPerRun(100, func() {
		common.Must2(pw.Write(data))
		reader.alloc.current = 2
		mb, err := reader.readMulti()
		common.Must(err)
		ReleaseMulti(mb)
	})
	// The returned MultiBuffer and its two Buffer headers.
	if n != 3 {
		t.Error("readMulti into two buffers: ", n, " allocs, want 3")
	}
}

// noCallRawConn returns from Read without calling f.
type noCallRawConn struct{ syscall.RawConn }

func (noCallRawConn) Read(func(fd uintptr) bool) error { return nil }

func TestReadVReaderReadMultiWithoutCallback(t *testing.T) {
	reader := NewReadVReader(nil, noCallRawConn{}, nil)
	reader.nBytes = Size // Left by an earlier read.
	reader.alloc.current = 2
	if mb, err := reader.readMulti(); mb != nil || err != io.EOF {
		t.Error("readMulti() = ", mb.Len(), " bytes, ", err, ", want 0 bytes, EOF")
	}
}
