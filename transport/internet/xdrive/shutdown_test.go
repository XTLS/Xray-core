package xdrive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type blockedUploadStore struct {
	*failPutStore
	started chan struct{}
	stopped chan struct{}
}

func (s *blockedUploadStore) block(ctx context.Context) error {
	close(s.started)
	<-ctx.Done()
	close(s.stopped)
	return ctx.Err()
}

func (s *blockedUploadStore) Put(ctx context.Context, name string, data []byte) error {
	if strings.HasSuffix(name, segSuffix) {
		return s.block(ctx)
	}
	return errors.New("unexpected upload after interrupt")
}

func (s *blockedUploadStore) setSlot(ctx context.Context, id, description string, body []byte) error {
	if frame, ok := decodeSlot(description); ok && frame.mode == slotInline {
		return s.block(ctx)
	}
	return s.memSlots.setSlot(ctx, id, description, body)
}

func receiveShutdownResult[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for XDRIVE shutdown")
		var zero T
		return zero
	}
}

func TestInterruptDuringClose(t *testing.T) {
	for _, mode := range []string{"slots", "WAL"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			store := &blockedUploadStore{
				failPutStore: &failPutStore{newMemSlots()},
				started:      make(chan struct{}),
				stopped:      make(chan struct{}),
			}
			p := paramsFromConfig(&Config{Concurrency: 2, SegmentBytes: 4096})
			released := make(chan bool, 1)
			onClose := func() {
				select {
				case <-store.stopped:
					released <- true
				default:
					released <- false
				}
			}

			var conn *Conn
			var closeStarted func() bool
			if mode == "slots" {
				r, err := makeRing(ctx, store, "interrupt", p)
				if err != nil {
					t.Fatal(err)
				}
				conn = newSlotConn(ctx, store, r.Up, r.Down, p, nil, onClose)
				w := conn.writer.(*slotWriter)
				closeStarted = func() bool {
					w.mu.Lock()
					defer w.mu.Unlock()
					return w.closed
				}
			} else {
				conn = newConn(ctx, store, "up", "down", p, onClose)
				w := conn.writer.(*walWriter)
				closeStarted = func() bool {
					w.mu.Lock()
					defer w.mu.Unlock()
					return w.closed
				}
			}
			if _, err := conn.Write(make([]byte, p.segmentBytes)); err != nil {
				t.Fatal(err)
			}
			receiveShutdownResult(t, store.started)

			closed := make(chan error, 1)
			go func() { closed <- conn.Close() }()
			waitFor(t, "graceful close to start", closeStarted)
			interrupted := make(chan error, 1)
			go func() {
				counted := &stat.CounterConnection{Connection: conn}
				interrupted <- common.Interrupt(stat.TryUnwrapStatsConn(counted))
			}()
			if err := receiveShutdownResult(t, interrupted); err != nil {
				t.Fatal(err)
			}
			if err := receiveShutdownResult(t, closed); !errors.Is(err, context.Canceled) {
				t.Fatalf("Close returned %v after interrupt", err)
			}
			if !receiveShutdownResult(t, released) {
				t.Fatal("storage was released before the upload stopped")
			}
			if _, err := conn.Write([]byte("late")); err == nil {
				t.Fatal("Write succeeded after interrupt")
			}
		})
	}
}

type gatedAnnounceStore struct {
	*failPutStore
	started chan struct{}
	release chan struct{}
	result  chan error
}

func (s *gatedAnnounceStore) Put(ctx context.Context, name string, data []byte) error {
	close(s.started)
	select {
	case <-ctx.Done():
	case <-s.release:
	}
	err := ctx.Err()
	s.result <- err
	return err
}

func TestShutdownWithPendingAnnouncement(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		name := "close"
		if interrupt {
			name = "interrupt"
		}
		t.Run(name, func(t *testing.T) {
			store := &gatedAnnounceStore{
				failPutStore: &failPutStore{newMemSlots()},
				started:      make(chan struct{}),
				release:      make(chan struct{}, 1),
				result:       make(chan error, 1),
			}
			defer close(store.release)
			factory := func(*Config) (Storage, error) { return store, nil }
			testStorageFactory.Store(&factory)
			defer testStorageFactory.Store(nil)
			config := &Config{Service: "sim", RemoteFolder: "test", Concurrency: 2}
			spareBoxFor(config).stop.Store(true)
			conn, err := Dial(t.Context(), net.Destination{}, &internet.MemoryStreamConfig{
				ProtocolName:     protocolName,
				ProtocolSettings: config,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			receiveShutdownResult(t, store.started)

			done := make(chan error, 1)
			if interrupt {
				go func() { done <- common.Interrupt(conn) }()
				if err := receiveShutdownResult(t, done); err != nil {
					t.Fatal(err)
				}
				if err := receiveShutdownResult(t, store.result); !errors.Is(err, context.Canceled) {
					t.Fatalf("announcement returned %v after interrupt", err)
				}
				return
			}

			go func() { done <- conn.Close() }()
			select {
			case err := <-done:
				t.Fatalf("Close returned %v while the announcement was pending", err)
			case <-time.After(50 * time.Millisecond):
			}
			store.release <- struct{}{}
			if err := receiveShutdownResult(t, done); err != nil {
				t.Fatal(err)
			}
			if err := receiveShutdownResult(t, store.result); err != nil {
				t.Fatalf("graceful close canceled the announcement: %v", err)
			}
		})
	}
}
