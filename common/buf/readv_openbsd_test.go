//go:build openbsd
// +build openbsd

package buf

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type openbsdTestCounter struct {
	mu    sync.Mutex
	total int64
}

func (c *openbsdTestCounter) Value() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

func (c *openbsdTestCounter) Set(v int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.total
	c.total = v
	return old
}

func (c *openbsdTestCounter) Add(delta int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.total
	c.total += delta
	return old
}

// tcpPair creates a real TCP client/server pair so tests exercise fd-backed
// sockets compatible with syscall.RawConn.
func tcpPair(tb testing.TB) (net.Conn, net.Conn, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		ln.Close()
		tb.Fatal(err)
	}
	server := <-ch
	if server == nil {
		client.Close()
		ln.Close()
		tb.Fatal("accept failed")
	}
	return server, client, func() {
		server.Close()
		client.Close()
		ln.Close()
	}
}

// rawConnOf unwraps net.Conn to syscall.RawConn used by ReadVReader internals.
func rawConnOf(tb testing.TB, conn net.Conn) syscall.RawConn {
	tb.Helper()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		tb.Fatal("conn does not implement syscall.Conn")
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		tb.Fatal(err)
	}
	return rc
}

// readSeqOnce directly invokes the platform multiReader once through RawConn.
// This isolates openbsdSeqReader.Read behavior from higher-level pipeline code.
func readSeqOnce(tb testing.TB, conn net.Conn, mr multiReader, bs []*Buffer) int32 {
	tb.Helper()
	mr.Init(bs)
	defer mr.Clear()

	rc := rawConnOf(tb, conn)
	var n int32
	if err := rc.Control(func(fd uintptr) {
		n = mr.Read(fd)
	}); err != nil {
		tb.Fatal(err)
	}
	return n
}

// readAll keeps draining ReadMultiBuffer until expected bytes are collected
// or EOF is reached; bytes are copied before ReleaseMulti.
func readAll(tb testing.TB, reader *ReadVReader, expected int) []byte {
	tb.Helper()
	got := make([]byte, 0, expected)
	for len(got) < expected {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			ReleaseMulti(mb)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			tb.Fatalf("unexpected error: %v", err)
		}
	}
	return got
}

// TestOpenBSDMultiReaderType ensures build-tag factory wiring returns the
// expected OpenBSD implementation.
func TestOpenBSDMultiReaderType(t *testing.T) {
	mr := newMultiReader()
	if mr == nil {
		t.Fatal("newMultiReader returned nil")
	}
	if _, ok := mr.(*openbsdSeqReader); !ok {
		t.Fatalf("expected *openbsdSeqReader, got %T", mr)
	}
}

// TestOpenBSDSmallPayload validates the end-to-end path for sub-buffer reads.
func TestOpenBSDSmallPayload(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	go func() {
		// Server writes once then closes to produce a clean EOF boundary.
		if _, err := server.Write(payload); err != nil {
			return
		}
		_ = server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	var got []byte
	for {
		// Collect all returned buffers before checking for termination.
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			ReleaseMulti(mb)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) >= len(payload) {
			break
		}
	}

	if len(got) != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), len(got))
	}
	for i, b := range payload {
		// Byte-for-byte check catches ordering/copy boundary bugs.
		if got[i] != b {
			t.Fatalf("data corruption at byte %d", i)
		}
	}
}

// TestOpenBSDLargePayload covers the original hang scenario under larger reads.
func TestOpenBSDLargePayload(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	const payloadSize = 32 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	go func() {
		// A single large write is enough to force multiple internal buffers.
		if _, err := server.Write(payload); err != nil {
			return
		}
		_ = server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	var got []byte
	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			ReleaseMulti(mb)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("error after %d bytes: %v", len(got), err)
		}
		if len(got) >= payloadSize {
			break
		}
	}

	if len(got) != payloadSize {
		t.Fatalf("expected %d bytes, got %d (deadline hit = original bug)", payloadSize, len(got))
	}
}

// TestOpenBSDSeqReaderEAGAINAtStart verifies idle socket behavior maps to -1.
func TestOpenBSDSeqReaderEAGAINAtStart(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()
	_ = server

	if err := client.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	mr := newMultiReader()
	b := New()
	defer b.Release()

	n := readSeqOnce(t, client, mr, []*Buffer{b})
	if n != -1 {
		t.Fatalf("expected -1 (EAGAIN/EWOULDBLOCK), got %d", n)
	}
}

// TestOpenBSDSeqReaderEINTRRetry verifies transient EINTR is retried in-place.
func TestOpenBSDSeqReaderEINTRRetry(t *testing.T) {
	b := New()
	defer b.Release()

	originalRead := openbsdRead
	defer func() {
		openbsdRead = originalRead
	}()

	calls := 0
	openbsdRead = func(fd int, p []byte) (int, error) {
		calls++
		if calls == 1 {
			// First call interrupted; second call should perform useful work.
			return 0, syscall.EINTR
		}
		return 17, nil
	}

	r := &openbsdSeqReader{}
	r.Init([]*Buffer{b})
	n := r.Read(1)
	r.Clear()

	if n != 17 {
		t.Fatalf("expected 17 after EINTR retry, got %d", n)
	}
	if calls != 2 {
		t.Fatalf("expected 2 read attempts, got %d", calls)
	}
}

type scriptedReadStep struct {
	wantBuf int
	n       int
	err     error
}

// TestOpenBSDSeqReaderScriptedScenarios runs deterministic syscall scripts to
// validate retry semantics and return-code contracts independent of socket timing.
func TestOpenBSDSeqReaderScriptedScenarios(t *testing.T) {
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	bufID := map[uintptr]int{
		uintptr(unsafe.Pointer(&b1.v[0])): 1,
		uintptr(unsafe.Pointer(&b2.v[0])): 2,
	}

	tests := []struct {
		name    string
		steps   []scriptedReadStep
		wantN   int32
		wantTry int
	}{
		{
			name: "eintr_retries_same_buffer_then_progress",
			steps: []scriptedReadStep{
				{wantBuf: 1, n: 0, err: syscall.EINTR},
				{wantBuf: 1, n: int(Size), err: nil},
				{wantBuf: 2, n: 0, err: syscall.EAGAIN},
			},
			wantN:   int32(Size),
			wantTry: 3,
		},
		{
			name: "fatal_without_progress_returns_neg_one",
			steps: []scriptedReadStep{
				{wantBuf: 1, n: 0, err: syscall.ECONNRESET},
			},
			wantN:   -1,
			wantTry: 1,
		},
		{
			name: "eof_without_progress_returns_zero",
			steps: []scriptedReadStep{
				{wantBuf: 1, n: 0, err: nil},
			},
			wantN:   0,
			wantTry: 1,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			originalRead := openbsdRead
			defer func() {
				openbsdRead = originalRead
			}()

			tries := 0
			openbsdRead = func(fd int, p []byte) (int, error) {
				if tries >= len(tc.steps) {
					t.Fatalf("unexpected extra read call: %d", tries+1)
				}
				step := tc.steps[tries]
				tries++

				gotBuf := bufID[uintptr(unsafe.Pointer(&p[0]))]
				if gotBuf != step.wantBuf {
					t.Fatalf("step %d: expected buffer %d, got %d", tries, step.wantBuf, gotBuf)
				}

				return step.n, step.err
			}

			r := &openbsdSeqReader{}
			r.Init([]*Buffer{b1, b2})
			n := r.Read(1)
			r.Clear()

			if n != tc.wantN {
				t.Fatalf("expected n=%d, got %d", tc.wantN, n)
			}
			if tries != tc.wantTry {
				t.Fatalf("expected %d read calls, got %d", tc.wantTry, tries)
			}
		})
	}
}

// TestOpenBSDSeqReaderEINTRBufferVisitInvariant stress-tests the retry loop
// with seeded scripts and checks that EINTR never advances to the next buffer.
func TestOpenBSDSeqReaderEINTRBufferVisitInvariant(t *testing.T) {
	const seeds = 16

	for seed := 0; seed < seeds; seed++ {
		seed := seed
		t.Run("seed_"+strconv.Itoa(seed), func(t *testing.T) {
			rnd := rand.New(rand.NewSource(int64(seed) + 404))

			b1 := New()
			b2 := New()
			b3 := New()
			defer b1.Release()
			defer b2.Release()
			defer b3.Release()

			bufID := map[uintptr]int{
				uintptr(unsafe.Pointer(&b1.v[0])): 1,
				uintptr(unsafe.Pointer(&b2.v[0])): 2,
				uintptr(unsafe.Pointer(&b3.v[0])): 3,
			}

			outcome := rnd.Intn(4)
			fullBeforeTail := rnd.Intn(3)
			shortTail := 1 + rnd.Intn(int(Size)-1)

			calls := 0
			lastBuf := 0
			var wantN int32

			openbsdReadOrig := openbsdRead
			defer func() {
				openbsdRead = openbsdReadOrig
			}()

			openbsdRead = func(fd int, p []byte) (int, error) {
				calls++
				buf := bufID[uintptr(unsafe.Pointer(&p[0]))]
				if buf == 0 {
					t.Fatalf("unknown buffer at call %d", calls)
				}

				if lastBuf != 0 && buf < lastBuf {
					t.Fatalf("buffer order regressed: last=%d current=%d", lastBuf, buf)
				}

				if rnd.Intn(3) == 0 {
					lastBuf = buf
					return 0, syscall.EINTR
				}

				if buf <= fullBeforeTail {
					lastBuf = buf
					wantN += int32(Size)
					return int(Size), nil
				}

				lastBuf = buf
				switch outcome {
				case 0:
					wantN += int32(shortTail)
					return shortTail, nil
				case 1:
					if wantN == 0 {
						wantN = -1
					}
					return 0, syscall.EAGAIN
				case 2:
					if wantN == 0 {
						wantN = -1
					}
					return 0, syscall.ECONNRESET
				default:
					if wantN == 0 {
						wantN = 0
					}
					return 0, nil
				}
			}

			r := &openbsdSeqReader{}
			r.Init([]*Buffer{b1, b2, b3})
			gotN := r.Read(1)
			r.Clear()

			if gotN != wantN {
				t.Fatalf("seed=%d: expected %d, got %d", seed, wantN, gotN)
			}
			if calls == 0 {
				t.Fatal("expected at least one syscall read")
			}
		})
	}
}

// TestOpenBSDSeqReaderEINTRThenEAGAIN ensures retry-on-EINTR still preserves
// non-ready signaling when next result is EAGAIN.
func TestOpenBSDSeqReaderEINTRThenEAGAIN(t *testing.T) {
	b := New()
	defer b.Release()

	originalRead := openbsdRead
	defer func() {
		openbsdRead = originalRead
	}()

	calls := 0
	openbsdRead = func(fd int, p []byte) (int, error) {
		calls++
		if calls == 1 {
			return 0, syscall.EINTR
		}
		return 0, syscall.EAGAIN
	}

	r := &openbsdSeqReader{}
	r.Init([]*Buffer{b})
	n := r.Read(1)
	r.Clear()

	if n != -1 {
		t.Fatalf("expected -1 after EINTR then EAGAIN, got %d", n)
	}
	if calls != 2 {
		t.Fatalf("expected 2 read attempts, got %d", calls)
	}
}

// TestOpenBSDSeqReaderEINTRAfterPartialPreservesTotal ensures bytes already
// read are never discarded when later calls encounter EINTR/EAGAIN.
func TestOpenBSDSeqReaderEINTRAfterPartialPreservesTotal(t *testing.T) {
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	originalRead := openbsdRead
	defer func() {
		openbsdRead = originalRead
	}()

	calls := 0
	openbsdRead = func(fd int, p []byte) (int, error) {
		calls++
		switch calls {
		case 1:
			return int(Size), nil
		case 2:
			return 0, syscall.EINTR
		default:
			// After one full buffer and one EINTR, next empty-read signal arrives.
			return 0, syscall.EAGAIN
		}
	}

	r := &openbsdSeqReader{}
	r.Init([]*Buffer{b1, b2})
	n := r.Read(1)
	r.Clear()

	if n != int32(Size) {
		t.Fatalf("expected %d bytes preserved after EINTR+EAGAIN, got %d", Size, n)
	}
	if calls != 3 {
		t.Fatalf("expected 3 read attempts, got %d", calls)
	}
}

// TestOpenBSDSeqReaderFatalErrorReturnsNegOne verifies that fatal errors
// (ECONNRESET, etc.) with no prior data return -1, allowing the Go runtime
// poller to detect the error via pollEventErr and propagate it to the caller
// as a real error instead of silently converting it to io.EOF.
func TestOpenBSDSeqReaderFatalErrorReturnsNegOne(t *testing.T) {
	b := New()
	defer b.Release()

	originalRead := openbsdRead
	defer func() { openbsdRead = originalRead }()

	openbsdRead = func(fd int, p []byte) (int, error) {
		return 0, syscall.ECONNRESET
	}

	r := &openbsdSeqReader{}
	r.Init([]*Buffer{b})
	n := r.Read(1)
	r.Clear()

	if n != -1 {
		t.Fatalf("expected -1 for fatal error with no prior data, got %d", n)
	}
}

// TestOpenBSDSeqReaderFatalErrorAfterPartialPreservesTotal verifies that when
// a fatal error occurs after some data has been read, the partial byte count
// is returned (deferring error to next call) rather than losing data.
func TestOpenBSDSeqReaderFatalErrorAfterPartialPreservesTotal(t *testing.T) {
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	originalRead := openbsdRead
	defer func() { openbsdRead = originalRead }()

	calls := 0
	openbsdRead = func(fd int, p []byte) (int, error) {
		calls++
		if calls == 1 {
			return int(Size), nil
		}
		return 0, syscall.ECONNRESET
	}

	r := &openbsdSeqReader{}
	r.Init([]*Buffer{b1, b2})
	n := r.Read(1)
	r.Clear()

	if n != int32(Size) {
		t.Fatalf("expected %d bytes preserved before fatal error, got %d", Size, n)
	}
}

// TestOpenBSDSeqReaderEAGAINMidLoop checks that partial progress is returned
// when a later buffer in the same cycle sees EAGAIN.
func TestOpenBSDSeqReaderEAGAINMidLoop(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, Size)
	if _, err := server.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	mr := newMultiReader()
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	n := readSeqOnce(t, client, mr, []*Buffer{b1, b2})
	if n != int32(Size) {
		t.Fatalf("expected partial read of %d, got %d", Size, n)
	}

	n = readSeqOnce(t, client, mr, []*Buffer{b1})
	if n != -1 {
		// After payload is fully consumed, socket should report not-ready.
		t.Fatalf("expected -1 after draining payload, got %d", n)
	}
}

// TestOpenBSDSeqReaderEOFMidLoop mirrors the EAGAIN-mid-loop case but with EOF.
func TestOpenBSDSeqReaderEOFMidLoop(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, Size)
	if _, err := server.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if tcpServer, ok := server.(*net.TCPConn); ok {
		if err := tcpServer.CloseWrite(); err != nil {
			t.Fatalf("close write failed: %v", err)
		}
	}

	mr := newMultiReader()
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	n := readSeqOnce(t, client, mr, []*Buffer{b1, b2})
	if n != int32(Size) {
		t.Fatalf("expected partial read of %d, got %d", Size, n)
	}

	n = readSeqOnce(t, client, mr, []*Buffer{b1})
	if n != 0 {
		t.Fatalf("expected EOF return 0 on next read, got %d", n)
	}
}

// TestOpenBSDSeqReaderShortReadBreak validates the short-read break invariant
// that readMulti relies on to map total bytes to buffer boundaries.
func TestOpenBSDSeqReaderShortReadBreak(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, Size+17)
	if _, err := server.Write(payload); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	mr := newMultiReader()
	b1 := New()
	b2 := New()
	b3 := New()
	defer b1.Release()
	defer b2.Release()
	defer b3.Release()

	n := readSeqOnce(t, client, mr, []*Buffer{b1, b2, b3})
	if n != int32(len(payload)) {
		t.Fatalf("expected %d bytes with short-read break, got %d", len(payload), n)
	}

	n = readSeqOnce(t, client, mr, []*Buffer{b1})
	if n != -1 {
		t.Fatalf("expected drained socket to return -1, got %d", n)
	}
}

// TestOpenBSDSeqReaderInitClearLifecycle verifies reader reuse does not keep
// stale buffer lengths across Init/Clear cycles.
func TestOpenBSDSeqReaderInitClearLifecycle(t *testing.T) {
	r, ok := newMultiReader().(*openbsdSeqReader)
	if !ok {
		t.Fatalf("unexpected reader type: %T", newMultiReader())
	}

	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	r.Init([]*Buffer{b1, b2})
	if len(r.bs) != 2 {
		t.Fatalf("expected bs len=2 after Init, got %d", len(r.bs))
	}

	r.Clear()
	if len(r.bs) != 0 {
		t.Fatalf("expected bs len=0 after Clear, got %d", len(r.bs))
	}

	r.Init([]*Buffer{b1})
	if len(r.bs) != 1 {
		t.Fatalf("expected bs len=1 after re-Init, got %d", len(r.bs))
	}
}

// TestOpenBSDSlowFragmentedRead checks correctness under many tiny writes and
// pauses where short reads and poll wakeups are frequent.
func TestOpenBSDSlowFragmentedRead(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() {
		for i := range payload {
			// Write one byte at a time to maximize fragmentation pressure.
			if _, err := server.Write(payload[i : i+1]); err != nil {
				return
			}
			time.Sleep(1 * time.Millisecond)
		}
		server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	var got []byte
	for len(got) < len(payload) {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			ReleaseMulti(mb)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if !bytes.Equal(got, payload) {
		t.Fatalf("fragmented read data mismatch: got=%d want=%d", len(got), len(payload))
	}
}

func TestOpenBSDSeqReaderZeroLengthBuffers(t *testing.T) {
	// Defensive case: empty allocation strategy slices should be harmless.
	server, client, cleanup := tcpPair(t)
	defer cleanup()
	_ = server

	mr := newMultiReader()

	n := readSeqOnce(t, client, mr, nil)
	if n != 0 {
		t.Fatalf("expected 0 for nil buffers, got %d", n)
	}

	n = readSeqOnce(t, client, mr, []*Buffer{})
	if n != 0 {
		t.Fatalf("expected 0 for empty buffers, got %d", n)
	}
}

// TestOpenBSDReadVReaderCounterMatchesBytes verifies counter accounting for
// the OpenBSD path matches exact payload bytes.
func TestOpenBSDReadVReaderCounterMatchesBytes(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	const payloadSize = 40 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i * 7) % 251)
	}

	go func() {
		if _, err := server.Write(payload); err != nil {
			return
		}
		_ = server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	counter := &openbsdTestCounter{}
	reader := NewReadVReader(client, rawConnOf(t, client), counter)

	got := readAll(t, reader, payloadSize)
	if len(got) != payloadSize {
		t.Fatalf("expected %d bytes, got %d", payloadSize, len(got))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if counter.Value() != int64(payloadSize) {
		t.Fatalf("counter mismatch: want %d got %d", payloadSize, counter.Value())
	}
}

// TestOpenBSDReadVReaderEOFImmediatelyAfterDrain checks EOF semantics after
// the caller has already drained all expected bytes.
func TestOpenBSDReadVReaderEOFImmediatelyAfterDrain(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	payload := make([]byte, 3*Size)
	for i := range payload {
		payload[i] = byte(i % 255)
	}

	go func() {
		if _, err := server.Write(payload); err != nil {
			return
		}
		if tcpServer, ok := server.(*net.TCPConn); ok {
			if err := tcpServer.CloseWrite(); err != nil {
				return
			}
			return
		}
		_ = server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	got := readAll(t, reader, len(payload))
	if len(got) != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), len(got))
	}

	_, err := reader.ReadMultiBuffer()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected immediate EOF after drain, got %v", err)
	}
}

// TestOpenBSDRandomFragmentedStream validates data integrity under randomized
// chunk sizes and intermittent idle gaps.
func TestOpenBSDRandomFragmentedStream(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	const payloadSize = 96 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i*31 + 17) % 251)
	}

	rnd := rand.New(rand.NewSource(42))
	go func() {
		written := 0
		for written < len(payload) {
			// Random chunking approximates bursty real-world network delivery.
			chunk := 1 + rnd.Intn(2048)
			if written+chunk > len(payload) {
				chunk = len(payload) - written
			}
			if _, err := server.Write(payload[written : written+chunk]); err != nil {
				return
			}
			written += chunk
			if rnd.Intn(4) == 0 {
				time.Sleep(time.Duration(rnd.Intn(3)+1) * time.Millisecond)
			}
		}
		server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)
	got := readAll(t, reader, payloadSize)

	if len(got) != payloadSize {
		t.Fatalf("expected %d bytes, got %d", payloadSize, len(got))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("random fragmented stream mismatch")
	}
}

// TestOpenBSDBoundarySizesMatrix exercises exact fence-post sizes around Size
// to catch off-by-one bugs in buffer slicing and remainder handling.
func TestOpenBSDBoundarySizesMatrix(t *testing.T) {
	testSizes := []int{
		Size - 1,
		Size,
		Size + 1,
		2*Size - 1,
		2 * Size,
		2*Size + 1,
		4*Size + 37,
	}

	for _, n := range testSizes {
		n := n
		t.Run("size_"+strconv.Itoa(n), func(t *testing.T) {
			server, client, cleanup := tcpPair(t)
			defer cleanup()

			payload := make([]byte, n)
			for i := range payload {
				payload[i] = byte((i*13 + 3) % 251)
			}

			go func() {
				// Single write keeps expected byte pattern deterministic per subtest.
				if _, err := server.Write(payload); err != nil {
					return
				}
				_ = server.Close()
			}()

			if err := client.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := NewReadVReader(client, rawConnOf(t, client), nil)
			got := readAll(t, reader, n)

			if len(got) != n {
				t.Fatalf("size=%d: got %d bytes", n, len(got))
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("size=%d: payload mismatch", n)
			}
		})
	}
}

// TestOpenBSDManyBurstsWithIdleGaps stresses repeated short/medium writes
// with regular idle windows.
func TestOpenBSDManyBurstsWithIdleGaps(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	rnd := rand.New(rand.NewSource(1337))
	const bursts = 220
	payload := make([]byte, 0, 220*1024)
	parts := make([][]byte, 0, bursts)
	for i := 0; i < bursts; i++ {
		chunk := 1 + rnd.Intn(2048)
		p := make([]byte, chunk)
		for j := range p {
			p[j] = byte((i*17 + j*7) % 251)
		}
		parts = append(parts, p)
		payload = append(payload, p...)
	}

	go func() {
		for i, p := range parts {
			if _, err := server.Write(p); err != nil {
				return
			}
			// Periodic gaps force reader to handle empty-socket poll cycles.
			if i%3 == 0 {
				time.Sleep(2 * time.Millisecond)
			}
		}
		server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)
	got := readAll(t, reader, len(payload))

	if len(got) != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), len(got))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("burst stream mismatch")
	}
}

// TestOpenBSDIntermittentEAGAINThenProgress verifies repeated readiness flips:
// no data loss while socket alternates between empty and writable phases.
func TestOpenBSDIntermittentEAGAINThenProgress(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	const payloadSize = 24 * 1024
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i*19 + 11) % 251)
	}

	go func() {
		written := 0
		for written < payloadSize {
			step := Size / 2
			if written+step > payloadSize {
				step = payloadSize - written
			}
			if _, err := server.Write(payload[written : written+step]); err != nil {
				return
			}
			written += step
			// Longer gaps force client polling cycles where socket is temporarily empty.
			time.Sleep(8 * time.Millisecond)
		}
		server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)
	got := readAll(t, reader, payloadSize)

	if len(got) != payloadSize {
		t.Fatalf("expected %d bytes, got %d", payloadSize, len(got))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("intermittent progress payload mismatch")
	}
}

// TestOpenBSDSeqReaderReuseAcrossPhases reuses the same multiReader across
// two traffic phases to validate lifecycle stability and EOF behavior.
func TestOpenBSDSeqReaderReuseAcrossPhases(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := client.SetReadDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	mr := newMultiReader()
	b1 := New()
	b2 := New()
	defer b1.Release()
	defer b2.Release()

	phase1 := make([]byte, Size+123)
	phase2 := make([]byte, 2*Size+19)
	for i := range phase1 {
		phase1[i] = byte((i*5 + 1) % 251)
	}
	for i := range phase2 {
		phase2[i] = byte((i*7 + 3) % 251)
	}

	phase1Ready := make(chan struct{})
	allowPhase2 := make(chan struct{})

	go func() {
		// Phase 1 and phase 2 are intentionally serialized to make boundaries explicit.
		if _, err := server.Write(phase1); err != nil {
			return
		}
		close(phase1Ready)
		<-allowPhase2
		if _, err := server.Write(phase2); err != nil {
			return
		}
		_ = server.Close()
	}()

	<-phase1Ready

	total := 0
	remainingPhase1 := len(phase1)
	for remainingPhase1 > 0 {
		// Each call should make forward progress until this phase is drained.
		n := readSeqOnce(t, client, mr, []*Buffer{b1, b2})
		if n <= 0 {
			t.Fatalf("unexpected non-progress read while phase1 has %d bytes remaining: %d", remainingPhase1, n)
		}
		total += int(n)
		remainingPhase1 -= int(n)
	}

	close(allowPhase2)

	remaining := len(phase2)
	for remaining > 0 {
		n := readSeqOnce(t, client, mr, []*Buffer{b1, b2})
		if n <= 0 {
			t.Fatalf("unexpected non-progress read while %d bytes remain: %d", remaining, n)
		}
		total += int(n)
		remaining -= int(n)
	}

	if total != len(phase1)+len(phase2) {
		t.Fatalf("total mismatch: want=%d got=%d", len(phase1)+len(phase2), total)
	}

	if n := readSeqOnce(t, client, mr, []*Buffer{b1}); n != 0 {
		// A final explicit EOF assertion protects against accidental retry loops.
		t.Fatalf("expected EOF after all phases drained, got %d", n)
	}
}

// TestOpenBSDPropertyFragmentedSeeds runs a seed matrix to broaden coverage
// against scheduler/network timing variance.
func TestOpenBSDPropertyFragmentedSeeds(t *testing.T) {
	seeds := 24
	if testing.Short() {
		seeds = 8
	}

	for seed := 0; seed < seeds; seed++ {
		seed := seed
		t.Run("seed_"+strconv.Itoa(seed), func(t *testing.T) {
			server, client, cleanup := tcpPair(t)
			defer cleanup()

			rnd := rand.New(rand.NewSource(int64(seed) + 9001))
			payloadSize := 4096 + rnd.Intn(192*1024)
			payload := make([]byte, payloadSize)
			for i := range payload {
				payload[i] = byte((i*31 + seed*17 + 9) % 251)
			}

			go func() {
				written := 0
				for written < len(payload) {
					// Larger random chunk range to hit many boundary combinations.
					chunk := 1 + rnd.Intn(4096)
					if written+chunk > len(payload) {
						chunk = len(payload) - written
					}
					if _, err := server.Write(payload[written : written+chunk]); err != nil {
						return
					}
					written += chunk
					if rnd.Intn(5) == 0 {
						time.Sleep(time.Duration(rnd.Intn(5)+1) * time.Millisecond)
					}
				}
				server.Close()
			}()

			if err := client.SetReadDeadline(time.Now().Add(12 * time.Second)); err != nil {
				t.Fatal(err)
			}
			reader := NewReadVReader(client, rawConnOf(t, client), nil)
			got := readAll(t, reader, payloadSize)

			if len(got) != payloadSize {
				t.Fatalf("seed=%d: expected=%d got=%d", seed, payloadSize, len(got))
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("seed=%d: payload mismatch", seed)
			}
		})
	}
}

// TestOpenBSDFatalErrorNoSpin verifies fatal socket errors terminate reads
// promptly and never spin in a tight retry loop.
func TestOpenBSDFatalErrorNoSpin(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := server.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}

	if err := client.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				ReleaseMulti(mb)
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMultiBuffer hung on fatal error (100% CPU spin regression)")
	}
}

// TestOpenBSDFatalErrorPropagatesAsNonEOF verifies that fatal socket teardown
// does not get silently converted to io.EOF at the ReadVReader boundary.
func TestOpenBSDFatalErrorPropagatesAsNonEOF(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	// Force an RST on close so the peer observes a fatal read-side condition.
	if err := server.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatalf("set linger failed: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server close failed: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for fatal read error")
		default:
		}

		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			ReleaseMulti(mb)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("expected non-EOF fatal error, got %v", err)
		}
		return
	}
}

// TestOpenBSDFatalErrorSubsequentReadStillFails quickly checks that after the
// first fatal read error, a subsequent read also terminates with an error
// rather than hanging or unexpectedly returning nil.
func TestOpenBSDFatalErrorSubsequentReadStillFails(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	if err := server.(*net.TCPConn).SetLinger(0); err != nil {
		t.Fatalf("set linger failed: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server close failed: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	readErr := func() error {
		deadline := time.After(3 * time.Second)
		for {
			select {
			case <-deadline:
				t.Fatal("timed out waiting for read error")
			default:
			}

			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				ReleaseMulti(mb)
			}
			if err != nil {
				return err
			}
		}
	}

	err1 := readErr()
	if errors.Is(err1, io.EOF) {
		t.Fatalf("expected first error to be non-EOF, got %v", err1)
	}

	err2 := readErr()
	if err2 == nil {
		t.Fatal("expected second read to fail after fatal teardown")
	}
}

// TestOpenBSDPartialThenFatalNonEOF verifies mixed lifecycle semantics:
// successful data delivery first, then fatal non-EOF teardown afterward.
func TestOpenBSDPartialThenFatalNonEOF(t *testing.T) {
	server, client, cleanup := tcpPair(t)
	defer cleanup()

	const payloadSize = 2048
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte((i*29 + 5) % 251)
	}

	triggerRST := make(chan struct{})
	go func() {
		if _, err := server.Write(payload); err != nil {
			return
		}
		<-triggerRST
		_ = server.(*net.TCPConn).SetLinger(0)
		_ = server.Close()
	}()

	if err := client.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatalf("set deadline failed: %v", err)
	}
	reader := NewReadVReader(client, rawConnOf(t, client), nil)

	var got []byte
	for len(got) < payloadSize {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			for _, b := range mb {
				got = append(got, b.Bytes()...)
			}
			ReleaseMulti(mb)
		}
		if err != nil {
			t.Fatalf("unexpected error while reading payload: %v", err)
		}
	}

	if !bytes.Equal(got[:payloadSize], payload) {
		t.Fatal("payload mismatch before fatal teardown")
	}

	close(triggerRST)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for fatal non-EOF error after payload")
		default:
		}

		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			ReleaseMulti(mb)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			t.Fatalf("expected non-EOF fatal error after payload, got %v", err)
		}
		return
	}
}

// BenchmarkOpenBSDSeqReader measures steady-state throughput for a continuous
// large-stream workload.
func BenchmarkOpenBSDSeqReader(b *testing.B) {
	server, client, cleanup := tcpPair(b)
	b.Cleanup(cleanup)

	const chunkSize = 1 << 20
	chunk := make([]byte, chunkSize)

	go func() {
		for {
			if _, err := server.Write(chunk); err != nil {
				return
			}
		}
	}()

	reader := NewReadVReader(client, rawConnOf(b, client), nil)
	b.SetBytes(chunkSize)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		var got int
		for got < chunkSize {
			// Drain exactly one chunk per iteration for stable bytes/op reporting.
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				got += int(mb.Len())
				ReleaseMulti(mb)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				b.Fatalf("bench error: %v", err)
			}
		}
	}
}

// BenchmarkOpenBSDMixedWorkload approximates irregular traffic patterns with
// random chunk sizes and occasional idle periods.
func BenchmarkOpenBSDMixedWorkload(b *testing.B) {
	server, client, cleanup := tcpPair(b)
	b.Cleanup(cleanup)

	const target = 64 * 1024

	rnd := rand.New(rand.NewSource(2026))
	go func() {
		buf := make([]byte, 64*1024)
		for {
			// Random write sizes emulate fluctuating application packetization.
			chunk := 1 + rnd.Intn(len(buf))
			if _, err := server.Write(buf[:chunk]); err != nil {
				return
			}
			if rnd.Intn(5) == 0 {
				time.Sleep(time.Duration(rnd.Intn(3)+1) * time.Millisecond)
			}
		}
	}()

	reader := NewReadVReader(client, rawConnOf(b, client), nil)
	b.SetBytes(target)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		got := 0
		for got < target {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				got += int(mb.Len())
				ReleaseMulti(mb)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				b.Fatalf("mixed bench error: %v", err)
			}
		}
	}
}
