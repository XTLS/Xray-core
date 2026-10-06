//go:build !wasm && !openbsd
// +build !wasm,!openbsd

package buf_test

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"golang.org/x/sync/errgroup"
)

func TestReadvReader(t *testing.T) {
	tcpServer := &tcp.Server{
		MsgProcessor: func(b []byte) []byte {
			return b
		},
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	common.Must(err)
	defer conn.Close()

	const size = 8192
	data := make([]byte, 8192)
	common.Must2(rand.Read(data))

	var errg errgroup.Group
	errg.Go(func() error {
		writer := NewWriter(conn)
		mb := MergeBytes(nil, data)

		return writer.WriteMultiBuffer(mb)
	})

	defer func() {
		if err := errg.Wait(); err != nil {
			t.Error(err)
		}
	}()

	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	common.Must(err)

	reader := NewReadVReader(conn, rawConn, nil)
	var rmb MultiBuffer
	for {
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal("unexpected error: ", err)
		}
		rmb, _ = MergeMulti(rmb, mb)
		if rmb.Len() == size {
			break
		}
	}

	rdata := make([]byte, size)
	SplitBytes(rmb, rdata)

	if r := cmp.Diff(data, rdata); r != "" {
		t.Fatal(r)
	}
}

// A connection that is reset while its reader waits for more ends the read with that error.
func TestReadvReaderReset(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	common.Must(err)
	defer conn.Close()
	peer, err := listener.Accept()
	common.Must(err)
	defer peer.Close()

	// a reader that has read full buffers asks for several of them at once, with readv
	reader := NewReader(conn)
	for size := Size; size <= 4*Size; size *= 2 {
		common.Must2(peer.Write(make([]byte, size)))
		time.Sleep(50 * time.Millisecond)
		mb, err := reader.ReadMultiBuffer()
		if err != nil || mb.Len() != int32(size) {
			t.Fatal("read: ", mb.Len(), ", expected: ", size, ", error: ", err)
		}
		ReleaseMulti(mb)
	}

	time.AfterFunc(50*time.Millisecond, func() {
		peer.(*net.TCPConn).SetLinger(0)
		peer.Close()
	})
	// without the error, the reader would wait for as long as the connection is left open
	common.Must(conn.SetReadDeadline(time.Now().Add(5 * time.Second)))
	start := time.Now()
	if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || err == nil || err == io.EOF || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("read: ", mb.Len(), ", error: ", err, ", after: ", time.Since(start))
	}
}
