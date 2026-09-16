package splithttp

import (
	"bufio"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

// readFrame reads one raw frame off the wire (as the CDN/client would see
// it, before any unframing) and reports its kind and size.
func readFrame(t *testing.T, r *bufio.Reader) (padding bool, size int) {
	t.Helper()
	raw, err := binary.ReadUvarint(r)
	if err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	padding = raw&1 != 0
	size = int(raw >> 1)
	if size > 0 {
		buf := make([]byte, size)
		if _, err := readFull(r, buf); err != nil {
			t.Fatalf("read frame body (%d bytes): %v", size, err)
		}
	}
	return
}

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// TestDownlinkPacerAlgorithm drives a real httpServerConn over a real HTTP
// connection and checks the on-wire frame sequence directly (bypassing
// framedReader, which is covered separately) to verify the actual trigger
// algorithm: no padding while writes keep coming, exactly one padding frame
// per idle period sized from flushBytes, falling back to cheap 0-byte
// keepalives if the idle period continues, and re-arming on the next write.
func TestDownlinkPacerAlgorithm(t *testing.T) {
	const flushDelayMs = 60
	const keepAliveSecs = 1 // coarse fallback interval, kept short so the test is fast
	var conn *httpServerConn
	ready := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn = &httpServerConn{
			Instance:       done.New(),
			ResponseWriter: w,
			framed:         true,
			activity:       make(chan struct{}, 1),
		}
		close(ready)
		go conn.runDownlinkPacer(
			keepAliveSecs*time.Second,
			&RangeConfig{From: 3000, To: 3000},
			&RangeConfig{From: flushDelayMs, To: flushDelayMs},
		)
		<-conn.Wait()
	}))
	defer srv.Close()

	c := &http.Client{}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-ready
	r := bufio.NewReaderSize(resp.Body, 1)

	// A burst of real writes close together must not trigger any padding in between.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
		}()
		conn.Write([]byte("data"))
		time.Sleep(flushDelayMs / 3 * time.Millisecond)
	}
	wg.Wait()
	for i := 0; i < 5; i++ {
		padding, size := readFrame(t, r)
		if padding || size != 4 {
			t.Fatalf("burst frame %d: got padding=%v size=%d, want a real 4-byte frame", i, padding, size)
		}
	}

	// Now go idle. The next frame must be exactly one padding flush, sized
	// from the configured range.
	padding, size := readFrame(t, r)
	if !padding || size != 3000 {
		t.Fatalf("post-idle frame: got padding=%v size=%d, want padding of 3000 bytes", padding, size)
	}

	// Idle continues: no more flush, just the cheap coarse keepalive (0-byte padding frame).
	padding, size = readFrame(t, r)
	if !padding || size != 0 {
		t.Fatalf("continued-idle frame: got padding=%v size=%d, want a 0-byte keepalive padding frame", padding, size)
	}

	// A new real write re-arms flush eligibility: the next idle period gets its own flush.
	conn.Write([]byte("more"))
	padding, size = readFrame(t, r)
	if padding || size != 4 {
		t.Fatalf("frame after re-arm write: got padding=%v size=%d, want the real write", padding, size)
	}
	padding, size = readFrame(t, r)
	if !padding || size != 3000 {
		t.Fatalf("frame after re-arm idle: got padding=%v size=%d, want a fresh padding flush", padding, size)
	}

	conn.Close()
}

// TestDownlinkPacerDisabledFlush checks that with flushBytes nil (the
// default, opt-in-only), idle periods only ever produce the cheap 0-byte
// keepalive padding frame -- no sized flush is ever written.
func TestDownlinkPacerDisabledFlush(t *testing.T) {
	var conn *httpServerConn
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn = &httpServerConn{Instance: done.New(), ResponseWriter: w, framed: true, activity: make(chan struct{}, 1)}
		close(ready)
		go conn.runDownlinkPacer(80*time.Millisecond, nil, &RangeConfig{From: 20, To: 20})
		<-conn.Wait()
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-ready
	r := bufio.NewReaderSize(resp.Body, 1)

	for i := 0; i < 3; i++ {
		padding, size := readFrame(t, r)
		if !padding || size != 0 {
			t.Fatalf("frame %d with flush disabled: got padding=%v size=%d, want a 0-byte keepalive padding frame", i, padding, size)
		}
	}
	conn.Close()
}

// TestDownlinkPacerZeroDelayFiresImmediately checks that a flushDelay of
// exactly 0 still reaches the flush (via time.After(0) in the normal wait,
// not a special case) instead of being treated as "nothing to wait for" and
// returning from the pacer -- that was the bug: delay <= 0 used to exit the
// whole goroutine whenever the computed wait came out non-positive,
// including the legitimate case of an exact-0 flush delay.
func TestDownlinkPacerZeroDelayFiresImmediately(t *testing.T) {
	var conn *httpServerConn
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn = &httpServerConn{Instance: done.New(), ResponseWriter: w, framed: true, activity: make(chan struct{}, 1)}
		close(ready)
		// keepAlive is coarse (10s); if a zero flushDelay wrongly returned
		// from the pacer instead of firing immediately, no flush frame would
		// ever show up and this test would time out reading it.
		go conn.runDownlinkPacer(10*time.Second, &RangeConfig{From: 512, To: 512}, &RangeConfig{From: 0, To: 0})
		<-conn.Wait()
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-ready
	r := bufio.NewReaderSize(resp.Body, 1)

	conn.Write([]byte("hi"))
	padding, size := readFrame(t, r)
	if padding || size != 2 {
		t.Fatalf("real write frame: got padding=%v size=%d", padding, size)
	}

	gotFlush := make(chan struct{})
	go func() {
		defer close(gotFlush)
		padding, size := readFrame(t, r)
		if !padding || size != 512 {
			t.Errorf("post-idle frame: got padding=%v size=%d, want an immediate 512-byte flush", padding, size)
		}
	}()
	select {
	case <-gotFlush:
	case <-time.After(5 * time.Second):
		t.Fatal("zero flushDelay never fired a flush -- pacer likely returned early")
	}
	conn.Close()
}

// TestDownlinkPacerNegativeDelayKeepsKeepAlive checks that a flushDelay
// resolving strictly negative only leaves that idle period's flush un-armed
// -- the pacer must still fall back to the plain keepalive at the keepAlive
// interval, not exit.
func TestDownlinkPacerNegativeDelayKeepsKeepAlive(t *testing.T) {
	var conn *httpServerConn
	ready := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn = &httpServerConn{Instance: done.New(), ResponseWriter: w, framed: true, activity: make(chan struct{}, 1)}
		close(ready)
		go conn.runDownlinkPacer(30*time.Millisecond, &RangeConfig{From: 512, To: 512}, &RangeConfig{From: -100, To: -1})
		<-conn.Wait()
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	<-ready
	r := bufio.NewReaderSize(resp.Body, 1)

	conn.Write([]byte("hi"))
	if padding, size := readFrame(t, r); padding || size != 2 {
		t.Fatalf("real write frame: got padding=%v size=%d", padding, size)
	}
	// With every flush delay resolving negative, the sized flush must never
	// fire -- but the pacer must keep producing the plain 0-byte keepalive
	// at the keepAlive interval, proving it didn't exit.
	for i := 0; i < 3; i++ {
		padding, size := readFrame(t, r)
		if !padding || size != 0 {
			t.Fatalf("frame %d: got padding=%v size=%d, want a 0-byte keepalive (flush must stay un-armed, not the pacer)", i, padding, size)
		}
	}
	conn.Close()
}
