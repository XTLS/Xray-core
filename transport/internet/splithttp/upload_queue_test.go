package splithttp_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

func Test_regression_readzero(t *testing.T) {
	q := NewUploadQueue(10)
	q.Push(Packet{
		Payload: []byte("x"),
		Seq:     0,
	})
	buf := make([]byte, 20)
	n, err := q.Read(buf)
	common.Must(err)
	if n != 1 {
		t.Error("n=", n)
	}
}

func Test_UploadQueueDropsDuplicateSeq(t *testing.T) {
	q := NewUploadQueue(10)
	a := bytes.Repeat([]byte{'a'}, 16384)
	b := make([]byte, 16384)
	for i := range b {
		b[i] = byte(i % 251)
	}
	// a client may resend seq 1 when a CDN in front of the server answers 502/504
	q.Push(Packet{Payload: b, Seq: 1})
	q.Push(Packet{Payload: bytes.Clone(b), Seq: 1})
	q.Push(Packet{Payload: a, Seq: 0})

	want := append(bytes.Clone(a), b...)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 8192)
	for len(got) < len(want) {
		n, err := q.Read(buf)
		common.Must(err)
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream corrupted")
	}

	q.Push(Packet{Payload: bytes.Clone(b), Seq: 1})
	q.Push(Packet{Payload: []byte("c"), Seq: 2})
	n, err := q.Read(buf)
	common.Must(err)
	for n == 0 {
		n, err = q.Read(buf)
		common.Must(err)
	}
	if string(buf[:n]) != "c" {
		t.Fatal("read a consumed seq again")
	}
}
