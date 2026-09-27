package mux

import (
	"context"
	"io"
	gonet "net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type blockedFrameSink struct {
	entered    chan struct{}
	release    chan struct{}
	once       sync.Once
	active     atomic.Int32
	concurrent atomic.Bool
	mu         sync.Mutex
	frames     [][]byte
}

type physicalFrameSink struct {
	conn    gonet.Conn
	entered chan struct{}
	once    sync.Once
}

func (s *physicalFrameSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	s.once.Do(func() { close(s.entered) })
	for _, b := range mb {
		if _, err := s.conn.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func TestE1StalledCarrierCancellationClosesAndJoins(t *testing.T) {
	for _, cause := range []string{"parent-cancel", "write-expiry"} {
		t.Run(cause, func(t *testing.T) {
			root, peer := gonet.Pipe()
			defer peer.Close()
			reader, writer := pipe.New()
			defer writer.Interrupt()
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := session.ContextWithInbound(parent, &session.Inbound{Conn: root})
			sink := &physicalFrameSink{conn: root, entered: make(chan struct{})}
			worker, err := NewServerWorker(ctx, nil, &transport.Link{Reader: reader, Writer: sink})
			if err != nil {
				t.Fatal(err)
			}
			defer worker.Close()
			// No jobs exist yet; the first channel handoff publishes this test budget.
			worker.frames.writeTimeout = time.Hour
			if cause == "write-expiry" {
				worker.frames.writeTimeout = 20 * time.Millisecond
			}
			dataDone := make(chan error, 1)
			go func() { dataDone <- worker.frames.submit(worker.ctx, []byte{1}, false) }()
			select {
			case <-sink.entered:
			case <-time.After(time.Second):
				t.Fatal("physical write not reached")
			}
			childCtx, childCancel := context.WithCancel(worker.ctx)
			child := &nativeChild{parent: worker, id: 11, ctx: childCtx, cancel: childCancel, inputDone: make(chan struct{})}
			if err := worker.nativeAdd(child); err != nil {
				t.Fatal(err)
			}
			childCancel()
			endDone := make(chan error, 1)
			go func() {
				defer worker.nativeWorkers.Done()
				defer worker.nativeRemove(child)
				endDone <- child.sendEnd(true)
			}()
			if cause == "parent-cancel" {
				cancel()
			}
			select {
			case <-worker.WaitJoined():
			case <-time.After(time.Second):
				t.Fatal("live stalled carrier did not join")
			}
			select {
			case <-dataDone:
			default:
				t.Fatal("data submission retained")
			}
			select {
			case <-endDone:
			default:
				t.Fatal("END submission retained")
			}
			if worker.ActiveConnections() != 0 {
				t.Fatal("child ID retained")
			}
			peer.SetReadDeadline(time.Now().Add(time.Second))
			var p [1]byte
			if _, err := peer.Read(p[:]); err != io.EOF {
				t.Fatalf("physical root not closed: %v", err)
			}
		})
	}
}

func (s *blockedFrameSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if s.active.Add(1) != 1 {
		s.concurrent.Store(true)
	}
	defer s.active.Add(-1)
	s.once.Do(func() { close(s.entered); <-s.release })
	var frame []byte
	for _, b := range mb {
		frame = append(frame, b.Bytes()...)
	}
	s.mu.Lock()
	s.frames = append(s.frames, frame)
	s.mu.Unlock()
	return nil
}

func TestE1CarrierSerializesOwnedFramesAfterChildCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sink := &blockedFrameSink{entered: make(chan struct{}), release: make(chan struct{})}
	carrier := newCarrierFrames(ctx, cancel, sink, time.Second)
	first := make(chan error, 1)
	go func() { first <- carrier.submit(ctx, []byte{1}, false) }()
	select {
	case <-sink.entered:
	case <-time.After(time.Second):
		t.Fatal("first frame not written")
	}
	childCtx, childCancel := context.WithCancel(ctx)
	second := make(chan error, 1)
	go func() { second <- carrier.submit(childCtx, []byte{2}, false) }()
	deadline := time.After(time.Second)
	for len(carrier.queue) == 0 {
		select {
		case <-deadline:
			t.Fatal("second frame not queued")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	childCancel()
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("canceled child still waits for carrier ACK")
	}
	if err := carrier.tryControl([]byte{3}); err != nil {
		t.Fatal(err)
	}
	close(sink.release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first frame not acknowledged")
	}
	deadline = time.After(time.Second)
	for {
		sink.mu.Lock()
		count := len(sink.frames)
		sink.mu.Unlock()
		if count == 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("carrier failed to drain owned frames")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	carrier.wait()
	if sink.concurrent.Load() {
		t.Fatal("carrier writer ran concurrently")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for i, frame := range sink.frames {
		if len(frame) != 1 || frame[0] != byte(i+1) {
			t.Fatalf("frame order=%v", sink.frames)
		}
	}
}

func TestE1ChildInputPressureIsLocal(t *testing.T) {
	carrierCtx, carrierCancel := context.WithCancel(context.Background())
	defer carrierCancel()
	aCtx, aCancel := context.WithCancel(carrierCtx)
	bCtx, bCancel := context.WithCancel(carrierCtx)
	defer bCancel()
	a := &nativeChild{ctx: aCtx, cancel: aCancel, frames: make(chan []byte, childInputFrames), inputDone: make(chan struct{})}
	b := &nativeChild{ctx: bCtx, cancel: bCancel, frames: make(chan []byte, childInputFrames), inputDone: make(chan struct{})}
	for i := 0; i < childInputFrames; i++ {
		a.enqueue([]byte{1})
	}
	a.enqueue([]byte{2})
	if a.ctx.Err() == nil {
		t.Fatal("overflow did not abort child")
	}
	if carrierCtx.Err() != nil {
		t.Fatal("child overflow canceled carrier")
	}
	b.enqueue([]byte{7})
	var p [1]byte
	if n, err := b.Read(p[:]); n != 1 || err != nil || p[0] != 7 {
		t.Fatalf("sibling read n=%d p=%d err=%v", n, p[0], err)
	}
}

func TestE1DuplicateChildIDCannotOverwrite(t *testing.T) {
	w := &ServerWorker{sessionManager: NewSessionManager(), native: make(map[uint16]*nativeChild)}
	a := &nativeChild{id: 9}
	b := &nativeChild{id: 9}
	if err := w.nativeAdd(a); err != nil {
		t.Fatal(err)
	}
	if err := w.nativeAdd(b); err == nil {
		t.Fatal("duplicate child accepted")
	}
	if w.nativeGet(9) != a {
		t.Fatal("original child replaced")
	}
	w.nativeRemove(a)
	w.nativeWorkers.Done()
	legacy := &Session{ID: 9, parent: w.sessionManager}
	if !w.sessionManager.Add(legacy) {
		t.Fatal("legacy add failed")
	}
	if w.sessionManager.Add(&Session{ID: 9, parent: w.sessionManager}) {
		t.Fatal("legacy duplicate overwrote session")
	}
}

func TestE1CarrierJoinClosesPhysicalRoot(t *testing.T) {
	root, peer := gonet.Pipe()
	defer peer.Close()
	inReader, inWriter := pipe.New()
	outReader, outWriter := pipe.New()
	defer inWriter.Interrupt()
	defer outReader.Interrupt()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: root})
	worker, err := NewServerWorker(ctx, nil, &transport.Link{Reader: inReader, Writer: outWriter})
	if err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	go func() { queued <- worker.frames.submit(worker.ctx, []byte{1}, false) }()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-worker.WaitJoined():
	case <-time.After(time.Second):
		t.Fatal("carrier did not join blocked work")
	}
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("queued frame submitter remained blocked")
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	var p [1]byte
	if _, err := peer.Read(p[:]); err != io.EOF {
		t.Fatalf("physical root not closed: %v", err)
	}
}
