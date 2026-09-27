package exchange

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type dataErrorReader struct {
	sent bool
	err  error
}

func (r *dataErrorReader) Read(p []byte) (int, error) {
	if r.sent {
		return 0, io.EOF
	}
	r.sent = true
	return copy(p, []byte("retained")), r.err
}
func (r *dataErrorReader) ReadTimeout(p []byte, _ time.Duration) (int, error) { return r.Read(p) }

func TestInputReplaysDataAndPendingError(t *testing.T) {
	wantErr := errors.New("read failed")
	in := NewInput(&dataErrorReader{err: wantErr}, nil)
	payload, err := in.Peek(32, time.Millisecond)
	if string(payload) != "retained" || !errors.Is(err, wantErr) {
		t.Fatalf("peek=%q %v", payload, err)
	}
	part := make([]byte, 3)
	n, err := in.Read(part)
	if n != 3 || string(part) != "ret" || err != nil {
		t.Fatalf("first=%q %v", part, err)
	}
	part = make([]byte, 16)
	n, err = in.Read(part)
	if string(part[:n]) != "ained" || !errors.Is(err, wantErr) {
		t.Fatalf("second=%q %v", part[:n], err)
	}
}

func TestAheadObservesEOFWhileConsumerBlocked(t *testing.T) {
	a, err := NewAhead(context.Background(), bytes.NewReader([]byte("last")), 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { a.Stop(); a.Join() }()
	select {
	case <-a.InputDone():
	case <-time.After(time.Second):
		t.Fatal("EOF was not observed independently")
	}
	p := make([]byte, 8)
	n, err := a.Read(p)
	if n != 4 || string(p[:n]) != "last" || err != nil {
		t.Fatalf("payload=%q %v", p[:n], err)
	}
	if _, err = a.Read(p); err != io.EOF {
		t.Fatalf("terminal=%v", err)
	}
}

func TestAheadPreservesZeroAndUnlimitedPolicy(t *testing.T) {
	for _, size := range []int32{0, -1} {
		a, err := NewAhead(context.Background(), bytes.NewReader(bytes.Repeat([]byte("data"), 16000)), size)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(a)
		a.Stop()
		a.Join()
		if err != nil || len(data) != 64000 {
			t.Fatalf("capacity=%d data=%d err=%v", size, len(data), err)
		}
	}
}

type blockingReader struct {
	stopped <-chan struct{}
	exited  *atomic.Bool
}

func (r blockingReader) Read([]byte) (int, error) {
	<-r.stopped
	r.exited.Store(true)
	return 0, io.EOF
}

func TestRunAbortJoinsBothDirectionsAndPreservesFailure(t *testing.T) {
	failure := errors.New("write failed")
	stopped := make(chan struct{})
	var exited atomic.Bool
	var closed atomic.Bool
	source := Stream{Reader: bytes.NewReader([]byte("data")), Writer: io.Discard, Abort: func() {
		if closed.CompareAndSwap(false, true) {
			close(stopped)
		}
	}}
	target := Stream{Reader: blockingReader{stopped: stopped, exited: &exited}, Writer: failingWriter{err: failure}, Abort: source.Abort}
	err := Run(context.Background(), source, target, time.Second, time.Second, time.Second)
	if !errors.Is(err, failure) {
		t.Fatalf("failure lost: %v", err)
	}
	if !exited.Load() {
		t.Fatal("downlink worker was not joined")
	}
}

func TestRunEOFPolicyOverridesActiveNativeTransfer(t *testing.T) {
	stopped := make(chan struct{})
	var exited, closed atomic.Bool
	abort := func() {
		if closed.CompareAndSwap(false, true) {
			close(stopped)
		}
	}
	source := Stream{Reader: bytes.NewReader(nil), Writer: io.Discard, NativeWrite: true, Abort: abort}
	target := Stream{Reader: blockingReader{stopped: stopped, exited: &exited}, Writer: io.Discard, NativeRead: true, Abort: abort}
	start := time.Now()
	err := Run(context.Background(), source, target, time.Second, 20*time.Millisecond, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("policy timeout result=%v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("downlink-only policy was suppressed for %v", elapsed)
	}
	if !exited.Load() {
		t.Fatal("blocked native direction was not joined")
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }
