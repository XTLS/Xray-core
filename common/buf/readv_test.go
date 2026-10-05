//go:build !wasm && !openbsd
// +build !wasm,!openbsd

package buf_test

import (
	"crypto/rand"
	"errors"
	"fmt"
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

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	common.Must(err)
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	common.Must(err)
	server, err := listener.Accept()
	common.Must(err)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	// a reader that is stuck fails with it
	common.Must(client.SetReadDeadline(time.Now().Add(5 * time.Second)))
	return client.(*net.TCPConn), server.(*net.TCPConn)
}

// What ends a read while it waits is what it returns. A reader that has read full buffers
// asks for eight of them at once, which is the only way to readMulti on Windows.
func TestReadvReaderErrors(t *testing.T) {
	for _, primed := range []bool{false, true} {
		setup := func(t *testing.T) (Reader, *net.TCPConn, *net.TCPConn) {
			client, server := tcpPair(t)
			reader := NewReader(client)
			for size := Size; primed && size <= 4*Size; size *= 2 {
				common.Must2(server.Write(make([]byte, size)))
				time.Sleep(50 * time.Millisecond)
				mb, err := reader.ReadMultiBuffer()
				if err != nil || mb.Len() != int32(size) {
					t.Fatal("read: ", mb.Len(), ", expected: ", size, ", error: ", err)
				}
				ReleaseMulti(mb)
			}
			return reader, client, server
		}
		t.Run(fmt.Sprint("EOF/primed=", primed), func(t *testing.T) {
			reader, _, server := setup(t)
			time.AfterFunc(50*time.Millisecond, func() {
				server.Write([]byte("abc"))
				time.Sleep(50 * time.Millisecond)
				server.Close()
			})
			if mb, err := reader.ReadMultiBuffer(); err != nil || mb.String() != "abc" {
				t.Fatal("read: ", mb.String(), ", error: ", err)
			}
			if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || err != io.EOF {
				t.Error("read: ", mb.Len(), ", error: ", err)
			}
		})
		t.Run(fmt.Sprint("Deadline/primed=", primed), func(t *testing.T) {
			reader, client, server := setup(t)
			common.Must(client.SetReadDeadline(time.Now().Add(50 * time.Millisecond)))
			if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("read: ", mb.Len(), ", error: ", err)
			}
			// a deadline that has passed wins over what has come, which stays for the next read
			common.Must2(server.Write([]byte("abc")))
			time.Sleep(50 * time.Millisecond)
			if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("read: ", mb.Len(), ", error: ", err)
			}
			common.Must(client.SetReadDeadline(time.Now().Add(5 * time.Second)))
			if mb, err := reader.ReadMultiBuffer(); err != nil || mb.String() != "abc" {
				t.Error("read: ", mb.String(), ", error: ", err)
			}
		})
		t.Run(fmt.Sprint("Close/primed=", primed), func(t *testing.T) {
			reader, client, _ := setup(t)
			time.AfterFunc(50*time.Millisecond, func() { client.Close() })
			if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || !errors.Is(err, net.ErrClosed) {
				t.Error("read: ", mb.Len(), ", error: ", err)
			}
		})
		// not a wait that never ends
		t.Run(fmt.Sprint("Reset/primed=", primed), func(t *testing.T) {
			reader, _, server := setup(t)
			time.AfterFunc(50*time.Millisecond, func() {
				server.SetLinger(0)
				server.Close()
			})
			if mb, err := reader.ReadMultiBuffer(); !mb.IsEmpty() || err == nil || err == io.EOF || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Error("read: ", mb.Len(), ", error: ", err)
			}
		})
	}
}

// bufferedConn has bytes that it read from its socket before.
type bufferedConn struct {
	*net.TCPConn
	buffered []byte
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	if len(c.buffered) > 0 {
		n := copy(b, c.buffered)
		c.buffered = c.buffered[n:]
		return n, nil
	}
	return c.TCPConn.Read(b)
}

// Only a *net.TCPConn has nothing in front of its socket: what else gives a socket is read through its Read.
func TestReadvReaderBufferedInFront(t *testing.T) {
	client, server := tcpPair(t)
	reader := NewReader(&bufferedConn{TCPConn: client, buffered: []byte("abc")})
	if _, ok := reader.(*ReadVReader); !ok {
		t.Fatal("reader is not a ReadVReader")
	}
	// nothing has come to the socket
	if mb, err := reader.ReadMultiBuffer(); err != nil || mb.String() != "abc" {
		t.Fatal("read: ", mb.String(), ", error: ", err)
	}
	common.Must2(server.Write([]byte("efg")))
	if mb, err := reader.ReadMultiBuffer(); err != nil || mb.String() != "efg" {
		t.Error("read: ", mb.String(), ", error: ", err)
	}
}
