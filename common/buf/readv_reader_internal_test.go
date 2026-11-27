//go:build !windows && !openbsd

package buf

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
)

func TestReadVReaderReadMultiAllocs(t *testing.T) {
	if runtime.GOOS != "linux" {
		// Elsewhere a pipe may return less than two buffers at once, which changes the count.
		t.Skip("the count is measured on Linux")
	}
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

type readResult struct {
	mb  MultiBuffer
	err error
}

// readMulti ends as conn.Read does on every event, both when the event comes before the read and
// when the read already waits for data.
func TestReadVReaderReadMultiEvents(t *testing.T) {
	for _, test := range []struct {
		name  string
		event func(client, server *net.TCPConn)
		bytes int32
		want  error
	}{
		{"data", func(_, server *net.TCPConn) { common.Must2(server.Write([]byte("abcd"))) }, 4, nil},
		{"close", func(_, server *net.TCPConn) { server.Close() }, 0, io.EOF},
		{"reset", func(_, server *net.TCPConn) {
			common.Must(server.SetLinger(0))
			server.Close()
		}, 0, syscall.ECONNRESET},
		{"local close", func(client, _ *net.TCPConn) { client.Close() }, 0, net.ErrClosed},
		{"deadline", func(client, _ *net.TCPConn) {
			common.Must(client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)))
		}, 0, os.ErrDeadlineExceeded},
	} {
		for _, waiting := range []bool{false, true} {
			name := test.name + "/before read"
			if waiting {
				name = test.name + "/while waiting"
			}
			t.Run(name, func(t *testing.T) {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				common.Must(err)
				defer ln.Close()
				dialed, err := net.Dial("tcp", ln.Addr().String())
				common.Must(err)
				defer dialed.Close()
				accepted, err := ln.Accept()
				common.Must(err)
				defer accepted.Close()
				client, server := dialed.(*net.TCPConn), accepted.(*net.TCPConn)

				rawConn, err := client.SyscallConn()
				common.Must(err)
				reader := NewReadVReader(client, rawConn, nil)
				if !waiting {
					test.event(client, server)
				}
				done := make(chan readResult, 1)
				go func() {
					mb, err := reader.readMulti()
					done <- readResult{mb, err}
				}()
				if waiting {
					time.Sleep(100 * time.Millisecond)
					test.event(client, server)
				}
				select {
				case r := <-done:
					if r.mb.Len() != test.bytes || !errors.Is(r.err, test.want) {
						t.Error("readMulti() = ", r.mb.Len(), " bytes, ", r.err, ", want ", test.bytes,
							" bytes, ", test.want)
					}
					ReleaseMulti(r.mb)
				case <-time.After(5 * time.Second):
					t.Error("readMulti() still waits")
				}
			})
		}
	}
}
