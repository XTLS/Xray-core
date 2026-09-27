package exchange

import (
	"bytes"
	"context"
	"errors"
	"github.com/xtls/xray-core/features/policy"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressEOFPolicyRunsDuringPreparation(t *testing.T) {
	size := int32(0)
	var closed atomic.Bool
	ctx, source, finish := Admit(context.Background(), Stream{Reader: bytes.NewReader([]byte("retained")), Writer: io.Discard, Abort: func() { closed.Store(true) }, ReadAhead: &size, Policy: &policy.Timeout{ConnectionIdle: time.Hour, DownlinkOnly: 10 * time.Millisecond, UplinkOnly: time.Hour}})
	defer finish()
	// No peer or Run exists: preparation must still be bounded by ingress policy.
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("preparation outlived ingress EOF policy")
	}
	_ = source
}

func TestPeerEOFDoesNotPrecedeFinalWrite(t *testing.T) {
	stopped := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	var exited atomic.Bool
	abort := func() { once.Do(func() { close(stopped) }) }
	source := Stream{Reader: bytes.NewReader([]byte("last")), Writer: io.Discard, Abort: abort, InputDone: closedChannel()}
	target := Stream{Reader: blockingReader{stopped: stopped, exited: &exited}, Writer: waitWriter{entered: entered, stopped: stopped}, Abort: abort}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, source, target, time.Hour, 0, time.Hour) }()
	<-entered
	select {
	case err := <-done:
		t.Fatalf("producer EOF ended peer before write: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("did not join")
	}
}

func TestResponseEOFPolicyAbortsAndJoinsBlockedFinalUplink(t *testing.T) {
	stopped := make(chan struct{})
	entered := make(chan struct{})
	var once sync.Once
	abort := func() { once.Do(func() { close(stopped) }) }
	source := Stream{Reader: bytes.NewReader([]byte("last")), Writer: io.Discard, Abort: abort}
	target := Stream{Reader: bytes.NewReader(nil), Writer: waitWriter{entered: entered, stopped: stopped}, Abort: abort}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), source, target, time.Hour, time.Hour, 10*time.Millisecond) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		abort()
		<-done
		t.Fatal("response EOF policy did not stop final uplink write")
	}
	select {
	case <-entered:
	default:
		t.Fatal("uplink writer was not exercised")
	}
}
func closedChannel() <-chan struct{} { c := make(chan struct{}); close(c); return c }

type waitWriter struct {
	entered chan struct{}
	stopped <-chan struct{}
}

func (w waitWriter) Write([]byte) (int, error) {
	close(w.entered)
	<-w.stopped
	return 0, io.ErrClosedPipe
}

func TestLiveProgressAndIdleForNativeFallback(t *testing.T) {
	upR, upW := io.Pipe()
	downR, downW := io.Pipe()
	var read, written atomic.Int64
	abort := func() { upR.Close(); upW.Close(); downR.Close(); downW.Close() }
	defer abort()
	source := Stream{Reader: upR, Writer: io.Discard, Abort: abort, NativeRead: true, NativeWrite: true, CountRead: func(n int64) { read.Add(n) }}
	target := Stream{Reader: downR, Writer: io.Discard, Abort: abort, NativeRead: true, NativeWrite: true, CountWrite: func(n int64) { written.Add(n) }}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), source, target, 25*time.Millisecond, time.Hour, time.Hour) }()
	if _, err := upW.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for written.Load() != 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if read.Load() != 4 || written.Load() != 4 {
		t.Fatalf("read=%d written=%d", read.Load(), written.Load())
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native fallback bypassed idle")
	}
}

func TestCloseWriteFailureIsReturned(t *testing.T) {
	want := errors.New("final framing failure")
	source := Stream{Reader: bytes.NewReader(nil), Writer: io.Discard}
	target := Stream{Reader: bytes.NewReader(nil), Writer: io.Discard, CloseWrite: func() error { return want }}
	if err := Run(context.Background(), source, target, time.Second, time.Second, time.Second); !errors.Is(err, want) {
		t.Fatalf("got %v", err)
	}
}

func TestLocalDiscardAbortsUnderlyingSource(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	done := make(chan error, 1)
	go func() { done <- Discard(Stream{Reader: r, Abort: func() { r.Close() }}, 10*time.Millisecond) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrHandled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("discard timer did not unblock source")
	}
}
