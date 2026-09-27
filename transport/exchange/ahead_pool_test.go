package exchange

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestAheadPartialReadsKeepPooledDataAndTerminal(t *testing.T) {
	for _, limit := range []int32{0, 64 * 1024, -1} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			payload := make([]byte, 2*1024*1024+317)
			for i := range payload {
				payload[i] = byte((i/31 + i*13) % 251)
			}
			failure := errors.New("terminal reader failure")
			a, err := NewAhead(context.Background(), &tailErrorReader{Reader: bytes.NewReader(payload), terminal: failure}, limit)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { a.Stop(); a.Join() }()
			var got bytes.Buffer
			p := make([]byte, 337)
			for {
				n, err := a.Read(p)
				got.Write(p[:n])
				if err != nil {
					if !errors.Is(err, failure) {
						t.Fatal(err)
					}
					break
				}
			}
			if !bytes.Equal(got.Bytes(), payload) {
				t.Fatal("pooled chunk changed before its final consumer copy")
			}
			select {
			case <-a.InputDone():
				t.Fatal("non-EOF terminal became policy EOF")
			default:
			}
		})
	}
}

type tailErrorReader struct {
	*bytes.Reader
	terminal error
}

func (r *tailErrorReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.Len() == 0 {
		return n, r.terminal
	}
	return n, err
}

func TestAheadProducerJoinPreservesAcceptedEOFData(t *testing.T) {
	a, err := NewAhead(context.Background(), bytes.NewReader([]byte("accepted")), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.Stop(); a.Join() }()
	a.Join() // EOF producer can finish before the consumer starts.
	p, err := io.ReadAll(a)
	if err != nil || string(p) != "accepted" {
		t.Fatalf("data=%q err=%v", p, err)
	}
}

func TestAheadAbortJoinReleasesPartiallyConsumedQueue(t *testing.T) {
	a, err := NewAhead(context.Background(), bytes.NewReader(bytes.Repeat([]byte{9}, 256*1024)), 64*1024)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := a.Read(make([]byte, 3)); n != 3 || err != nil {
		t.Fatal(n, err)
	}
	a.Stop()
	a.Join()
	a.Join()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.queue) != 0 || a.size != 0 {
		t.Fatalf("retained queue=%d bytes=%d", len(a.queue), a.size)
	}
}

func TestAheadConcurrentConsumersOfPoolNeverShareLiveStorage(t *testing.T) {
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func(id int) {
			defer workers.Done()
			want := bytes.Repeat([]byte{byte(id + 1)}, 512*1024)
			a, err := NewAhead(context.Background(), bytes.NewReader(want), 0)
			if err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(a)
			a.Stop()
			a.Join()
			if err != nil || !bytes.Equal(got, want) {
				t.Errorf("stream %d corrupted: %v", id, err)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("lost queue notification")
	}
}

func BenchmarkAheadOwnedTransfer(b *testing.B) {
	for _, size := range []int{1024, 1024 * 1024} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			payload := bytes.Repeat([]byte{17}, size)
			buffer := make([]byte, 16*1024)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a, err := NewAhead(context.Background(), bytes.NewReader(payload), 64*1024)
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.CopyBuffer(io.Discard, a, buffer)
				a.Stop()
				a.Join()
				if err != nil || n != int64(size) {
					b.Fatal(n, err)
				}
			}
		})
	}
}
