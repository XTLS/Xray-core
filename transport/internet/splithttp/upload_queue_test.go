package splithttp_test

import (
	"crypto/rand"
	"io"
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

func Test_uploadQueue_orderReassembly(t *testing.T) {
	q := NewUploadQueue(10)
	defer q.Close()

	// Push out of order
	_ = q.Push(Packet{Payload: []byte("world"), Seq: 1})
	_ = q.Push(Packet{Payload: []byte("hello"), Seq: 0})

	buf := make([]byte, 20)
	n, err := q.Read(buf)
	common.Must(err)
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got '%s'", string(buf[:n]))
	}

	n, err = q.Read(buf)
	common.Must(err)
	if string(buf[:n]) != "world" {
		t.Errorf("expected 'world', got '%s'", string(buf[:n]))
	}
}

func Test_uploadQueue_largePayloadPooling(t *testing.T) {
	q := NewUploadQueue(10)
	defer q.Close()

	// Simulate large payloads similar to real XHTTP traffic
	payload := make([]byte, 256000)
	_, _ = rand.Read(payload)

	for i := 0; i < 5; i++ {
		p := make([]byte, len(payload))
		copy(p, payload)
		_ = q.Push(Packet{Payload: p, Seq: uint64(i)})

		readBuf := make([]byte, 256000)
		n, err := q.Read(readBuf)
		common.Must(err)
		if n != len(payload) {
			t.Errorf("iteration %d: expected %d bytes, got %d", i, len(payload), n)
		}
	}
}

func Test_uploadQueue_partialRead(t *testing.T) {
	q := NewUploadQueue(10)
	defer q.Close()

	_ = q.Push(Packet{Payload: []byte("helloworld"), Seq: 0})

	// Read only 5 bytes — remainder should stay in queue
	buf := make([]byte, 5)
	n, err := q.Read(buf)
	common.Must(err)
	if string(buf[:n]) != "hello" {
		t.Errorf("expected 'hello', got '%s'", string(buf[:n]))
	}

	// Read remainder
	n, err = q.Read(buf)
	common.Must(err)
	if string(buf[:n]) != "world" {
		t.Errorf("expected 'world', got '%s'", string(buf[:n]))
	}
}

func Test_uploadQueue_closeReturnsEOF(t *testing.T) {
	q := NewUploadQueue(10)
	_ = q.Push(Packet{Payload: []byte("data"), Seq: 0})
	q.Close()

	buf := make([]byte, 20)
	// Should be able to read already-pushed data even after close
	_, err := q.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("unexpected error: %v", err)
	}
}

// Benchmark measures allocations per push/read cycle.
// After optimization with buffer pooling, allocations should decrease.
func BenchmarkUploadQueue_PushReadCycle(b *testing.B) {
	payload := make([]byte, 256000) // typical scMaxEachPostBytes
	_, _ = rand.Read(payload)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		q := NewUploadQueue(10)
		p := make([]byte, len(payload))
		copy(p, payload)
		_ = q.Push(Packet{Payload: p, Seq: 0})
		readBuf := make([]byte, 256000)
		_, _ = q.Read(readBuf)
		q.Close()
	}
}
