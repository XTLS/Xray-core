//go:build !wasm
// +build !wasm

package buf_test

import (
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/testing/servers/tcp"
	"golang.org/x/sync/errgroup"
)

// testCounter is a minimal stats.Counter implementation for testing.
type testCounter struct {
	mu    sync.Mutex
	total int64
}

func (c *testCounter) Value() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

func (c *testCounter) Set(v int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.total
	c.total = v
	return old
}

func (c *testCounter) Add(delta int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.total
	c.total += delta
	return old
}

func TestReadvReader(t *testing.T) {
	// Echo server keeps payload shape unchanged so this test only validates
	// reader/writer buffering logic and not transformation semantics.
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
		// Read until exactly one logical frame is reconstructed.
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

// TestReadvReaderMultiBuffer sends 64 KB through the ReadVReader so that
// the allocStrategy advances past 1 and triggers the readMulti() code path.
// This covers: allocStrategy.Alloc, readMulti(), posixReader.Init/Read/Clear.
func TestReadvReaderMultiBuffer(t *testing.T) {
	// This path intentionally sends more than one buffer so the adaptive strategy
	// scales above the single-buffer path and drives readMulti coverage.
	tcpServer := &tcp.Server{
		MsgProcessor: func(b []byte) []byte { return b },
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	common.Must(err)
	defer conn.Close()

	const size = 64 * 1024
	data := make([]byte, size)
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
	for rmb.Len() < size {
		// Accumulate until we reconstruct all bytes from the sender.
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal("unexpected error: ", err)
		}
		rmb, _ = MergeMulti(rmb, mb)
	}

	rdata := make([]byte, size)
	SplitBytes(rmb, rdata)
	if r := cmp.Diff(data, rdata); r != "" {
		t.Fatal(r)
	}
}

// TestReadvReaderCounter verifies the stats.Counter is incremented correctly
// for both the single-buffer and multi-buffer read paths.
func TestReadvReaderCounter(t *testing.T) {
	// Counter wiring is verified against exact payload size to catch both
	// undercounting and accidental double-counting across read modes.
	tcpServer := &tcp.Server{
		MsgProcessor: func(b []byte) []byte { return b },
	}
	dest, err := tcpServer.Start()
	common.Must(err)
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	common.Must(err)
	defer conn.Close()

	const size = 64 * 1024
	data := make([]byte, size)
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

	counter := &testCounter{}
	reader := NewReadVReader(conn, rawConn, counter)
	var total int
	for total < size {
		// Counter increments internally per successful read call.
		mb, err := reader.ReadMultiBuffer()
		if err != nil {
			t.Fatal("unexpected error: ", err)
		}
		total += int(mb.Len())
		ReleaseMulti(mb)
	}

	if counter.Value() != int64(size) {
		t.Fatalf("counter mismatch: expected %d, got %d", size, counter.Value())
	}
}

// TestReadvReaderMultiEOF exercises the EOF path inside readMulti.
//
// After reading one full buffer (8192 B), the allocStrategy advances current
// to 2, so the next ReadMultiBuffer call enters readMulti().  The server has
// already closed the connection at that point, so the OS returns 0 bytes and
// readMulti correctly propagates io.EOF.
func TestReadvReaderMultiEOF(t *testing.T) {
	// Use real TCP sockets (not net.Pipe) so SyscallConn-backed paths are tested.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write exactly one full buffer and close. The client will read it,
		// advance alloc to 2, and then encounter EOF through readMulti().
		data := make([]byte, Size)
		if _, err := conn.Write(data); err != nil {
			return
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.(*net.TCPConn).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	rawConn, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	reader := NewReadVReader(client, rawConn, nil)
	var total int
	var gotEOF bool
	for !gotEOF {
		// First read drains one full buffer, second call should hit EOF via readMulti.
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			total += int(mb.Len())
			ReleaseMulti(mb)
		}
		if errors.Is(err, io.EOF) {
			gotEOF = true
		} else if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if total != Size {
		t.Fatalf("expected %d bytes, got %d", Size, total)
	}
}

// TestReadvReaderRawConnError exercises the rawConn.Read error path inside
// readMulti.  After the first full buffer advances alloc to 2, a tight
// deadline fires during the second ReadMultiBuffer (multi-buffer path),
// causing rawConn.Read itself to return an error.
func TestReadvReaderRawConnError(t *testing.T) {
	// The goal is to force rawConn.Read itself to fail while in multi-buffer mode.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write one full buffer, then hold the connection open so the client
		// enters readMulti and blocks waiting for more data.
		data := make([]byte, Size)
		if _, err := conn.Write(data); err != nil {
			return
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			return
		}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	rawConn, err := client.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	reader := NewReadVReader(client, rawConn, nil)

	// First read: must return a full buffer so allocStrategy advances to 2.
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal("first read error:", err)
	}
	if mb.Len() < Size {
		ReleaseMulti(mb)
		// Without a full first read, allocStrategy may not enter multi mode.
		t.Skipf("first read returned only %d bytes (< %d); skipping rawConn error coverage path", mb.Len(), Size)
	}
	ReleaseMulti(mb)

	// Expire the deadline before the next read so rawConn.Read fails.
	if err := client.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)

	mb, err = reader.ReadMultiBuffer()
	if mb != nil {
		ReleaseMulti(mb)
	}
	if err == nil {
		t.Fatal("expected error from timed-out rawConn.Read, got nil")
	}
	netErr, ok := err.(net.Error)
	if !ok || !netErr.Timeout() {
		t.Fatalf("expected timeout error, got: %v", err)
	}
}
