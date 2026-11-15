package encoding

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type testHunkConn struct {
	hunks []*Hunk
}

func (c *testHunkConn) Context() context.Context    { return context.Background() }
func (c *testHunkConn) Send(*Hunk) error            { return nil }
func (c *testHunkConn) SendMsg(m interface{}) error { return nil }
func (c *testHunkConn) RecvMsg(m interface{}) error { return nil }
func (c *testHunkConn) Recv() (*Hunk, error) {
	if len(c.hunks) == 0 {
		return nil, io.EOF
	}
	h := c.hunks[0]
	c.hunks = c.hunks[1:]
	return h, nil
}

type testMultiHunkConn struct {
	hunks []*MultiHunk
}

func (c *testMultiHunkConn) Context() context.Context    { return context.Background() }
func (c *testMultiHunkConn) Send(*MultiHunk) error       { return nil }
func (c *testMultiHunkConn) SendMsg(m interface{}) error { return nil }
func (c *testMultiHunkConn) RecvMsg(m interface{}) error { return nil }
func (c *testMultiHunkConn) Recv() (*MultiHunk, error) {
	if len(c.hunks) == 0 {
		return nil, io.EOF
	}
	h := c.hunks[0]
	c.hunks = c.hunks[1:]
	return h, nil
}

func readAll(t *testing.T, reader buf.Reader) []byte {
	t.Helper()
	var data []byte
	for {
		mb, err := reader.ReadMultiBuffer()
		for _, b := range mb {
			if b.Len() > buf.Size {
				t.Fatalf("got a buffer of %d bytes, larger than buf.Size", b.Len())
			}
			data = append(data, b.Bytes()...)
		}
		buf.ReleaseMulti(mb)
		if err != nil {
			return data
		}
	}
}

// Other gRPC clients put more than buf.Size bytes in one hunk (sing-box writes up to 32 KiB).
func hunkSizes() []int {
	return []int{100, buf.Size - 1, buf.Size, buf.Size + 1, 32 * 1024}
}

func TestHunkReaderWriterBufferSize(t *testing.T) {
	var hunks []*Hunk
	var want []byte
	for _, size := range hunkSizes() {
		data := make([]byte, size)
		rand.Read(data)
		hunks = append(hunks, &Hunk{Data: data})
		want = append(want, data...)
	}

	got := readAll(t, NewHunkReadWriter(&testHunkConn{hunks: hunks}, nil))
	if !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes, want %d bytes of the same content", len(got), len(want))
	}
}

func TestMultiHunkReaderWriterBufferSize(t *testing.T) {
	var data [][]byte
	var want []byte
	for _, size := range hunkSizes() {
		b := make([]byte, size)
		rand.Read(b)
		data = append(data, b)
		want = append(want, b...)
	}

	got := readAll(t, NewMultiHunkReadWriter(&testMultiHunkConn{hunks: []*MultiHunk{{Data: data}}}, nil))
	if !bytes.Equal(got, want) {
		t.Fatalf("read %d bytes, want %d bytes of the same content", len(got), len(want))
	}
}
