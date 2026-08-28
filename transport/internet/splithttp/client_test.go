package splithttp_test

import (
	"io"
	"sync"
	"sync/atomic"
	"testing"

	. "github.com/xtls/xray-core/transport/internet/splithttp"
)

// nilDerefBody mirrors the shape of http2.transportResponseBody: a struct whose
// only field is a pointer that its methods dereference. A torn read of the
// interface value yields a non-nil interface holding a zero struct, so calling
// through it panics, which is what the reported crash was.
type nilDerefBody struct{ p *int }

func (b nilDerefBody) Read(_ []byte) (int, error) { _ = *b.p; return 0, io.EOF }
func (b nilDerefBody) Close() error               { _ = *b.p; return nil }

// OpenStream returns the WaitReadCloser right after GotConn, while the response
// body only arrives later, on the goroutine that runs client.Do. By then the
// consumer may already be inside Read (splitConn.Read), and splitConn.Close may
// fire from another goroutine, so Set, Read and Close all run concurrently.
//
// Under -race this fails deterministically. Without -race it still catches the
// bug through the nil dereference above, though only probabilistically.
func Test_regression_WaitReadCloser_race(t *testing.T) {
	var panics int64
	value := 1

	for i := 0; i < 500000; i++ {
		w := &WaitReadCloser{Wait: make(chan struct{})}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer func() {
				if recover() != nil {
					atomic.AddInt64(&panics, 1)
				}
			}()
			b := make([]byte, 8)
			w.Read(b)
		}()
		go func() {
			defer wg.Done()
			defer func() {
				if recover() != nil {
					atomic.AddInt64(&panics, 1)
				}
			}()
			w.Close()
		}()

		w.Set(nilDerefBody{p: &value})
		wg.Wait()
	}

	if n := atomic.LoadInt64(&panics); n != 0 {
		t.Error("nil dereference through a torn interface read, count: ", n)
	}
}
