package dispatcher

import (
	sync "sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/xtls/xray-core/common/buf"
)

// mockWriter for testing
type mockWriter struct {
	written int64
}

func (w *mockWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.written += int64(mb.Len())
	buf.ReleaseMulti(mb)
	return nil
}

func (w *mockWriter) Close() error { return nil }

func TestRateLimitedWriter_Basic(t *testing.T) {
	mock := &mockWriter{}
	limiter := rate.NewLimiter(rate.Limit(10000), 10000)
	writer := NewRateLimitedWriter(mock, limiter, nil)

	b := buf.New()
	b.Write([]byte("hello world"))
	mb := buf.MultiBuffer{b}

	err := writer.WriteMultiBuffer(mb)
	if err != nil {
		t.Errorf("WriteMultiBuffer failed: %v", err)
	}

	if mock.written != 11 {
		t.Errorf("Expected 11 bytes written, got %d", mock.written)
	}
}

func TestRateLimitedWriter_RateLimit(t *testing.T) {
	mock := &mockWriter{}
	// 64KB/s rate with 64KB burst
	const rateBytesPerSec = 64 * 1024
	limiter := rate.NewLimiter(rate.Limit(rateBytesPerSec), rateBytesPerSec)
	writer := NewRateLimitedWriter(mock, limiter, nil)

	// Write 8 times to consume burst (~64KB)
	data := make([]byte, 8000)
	for i := 0; i < 8; i++ {
		b := buf.New()
		b.Write(data)
		writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}

	// Next write should be rate limited
	b := buf.New()
	smallData := make([]byte, 6400) // ~10% of rate
	b.Write(smallData)

	start := time.Now()
	writer.WriteMultiBuffer(buf.MultiBuffer{b})
	duration := time.Since(start)

	// Should take at least 50ms but not too long (avoid detecting deadlock)
	if duration < 50*time.Millisecond {
		t.Errorf("Write after burst should be rate limited, took: %v", duration)
	}
	if duration > 2*time.Second {
		t.Errorf("Write took too long, possible deadlock: %v", duration)
	}
}

func TestRateLimitedWriter_NoLimit(t *testing.T) {
	mock := &mockWriter{}
	limiter := rate.NewLimiter(rate.Limit(0), 0) // Should default to infinite ideally, or handle 0
	// Wait, rate.NewLimiter(0, 0) means reject all events if allow is called?
	// NewRateLimitedWriter logic checks for limit > 0.
	// rate.NewLimiter(0, x) means limit is 0 events/sec.

	// Previous logic was: bytesPerSec 0 -> no limit.
	// Now logic inside NewRateLimitedWriter: if w.limiter != nil && w.limiter.Limit() > 0 { ... }
	// So passing limit 0 is fine, it will bypass the limiter logic loop.

	writer := NewRateLimitedWriter(mock, limiter, nil)

	for i := 0; i < 10; i++ {
		b := buf.New()
		b.Write(make([]byte, 1000))
		start := time.Now()
		err := writer.WriteMultiBuffer(buf.MultiBuffer{b})
		if err != nil {
			t.Errorf("Write failed: %v", err)
		}
		// Use 200ms threshold to avoid flaky tests on slow CI machines
		if time.Since(start) > 200*time.Millisecond {
			t.Error("No-limit write should be fast")
		}
	}
}

func TestRateLimitedWriter_WithCounter(t *testing.T) {
	mock := &mockWriter{}
	counter := &mockCounter{}
	limiter := rate.NewLimiter(rate.Limit(10000), 10000)
	writer := NewRateLimitedWriter(mock, limiter, counter)

	b := buf.New()
	b.Write([]byte("test data"))
	writer.WriteMultiBuffer(buf.MultiBuffer{b})

	if counter.Value() != 9 {
		t.Errorf("Counter should be 9, got %d", counter.Value())
	}
}

func TestRateLimitedWriter_Close(t *testing.T) {
	mock := &mockWriter{}
	limiter := rate.NewLimiter(rate.Limit(1000), 1000)
	writer := NewRateLimitedWriter(mock, limiter, nil)

	writer.Close()

	b := buf.New()
	b.Write([]byte("test"))
	err := writer.WriteMultiBuffer(buf.MultiBuffer{b})
	if err == nil {
		t.Error("Expected error when writing to closed writer")
	}
}

func TestRateLimitedWriter_SharedLimiter(t *testing.T) {
	// Total limit 10KB/s
	const rateBytesPerSec = 10 * 1024
	// Use small burst
	limiter := rate.NewLimiter(rate.Limit(rateBytesPerSec), 1024)

	// User opens 5 connections
	const concurrentConns = 5
	writers := make([]*RateLimitedWriter, concurrentConns)
	mocks := make([]*mockWriter, concurrentConns)

	for i := 0; i < concurrentConns; i++ {
		mocks[i] = &mockWriter{}
		writers[i] = NewRateLimitedWriter(mocks[i], limiter, nil)
	}

	// Each connection tries to write 4KB (Total 20KB)
	dataSize := 4 * 1024
	data := make([]byte, dataSize)

	start := time.Now()
	var wg sync.WaitGroup
	errCh := make(chan error, concurrentConns)

	for i := 0; i < concurrentConns; i++ {
		wg.Add(1)
		go func(w *RateLimitedWriter) {
			defer wg.Done()
			b := buf.New()
			b.Write(data)
			if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
				errCh <- err
			}
		}(writers[i])
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("Write failed: %v", err)
	}

	duration := time.Since(start)

	// Total written: 20KB. Limit: 10KB/s. Burst: 1KB.
	// Expected time approx 1.9 seconds.

	if duration < 1500*time.Millisecond {
		t.Errorf("Shared limiter failed, too fast: %v. Expected > 1.5s", duration)
	}
}

// mockCounter implements stats.Counter
type mockCounter struct {
	value int64
}

func (c *mockCounter) Value() int64      { return c.value }
func (c *mockCounter) Set(v int64) int64 { old := c.value; c.value = v; return old }
func (c *mockCounter) Add(v int64) int64 { old := c.value; c.value += v; return old }
