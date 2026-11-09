package xdrive

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// badBodySlots serves a media frame whose body never matches its checksum.
type badBodySlots struct{}

func (badBodySlots) makeSlot(ctx context.Context, name string) (string, error) { return name, nil }
func (badBodySlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	return nil
}
func (badBodySlots) readDescription(ctx context.Context, id string) (string, error) {
	return newSlotFrame(0, slotMedia, make([]byte, 64)).encode(), nil
}
func (badBodySlots) readBody(ctx context.Context, id string) ([]byte, error) {
	return bytes.Repeat([]byte{1}, 64), nil
}

// emptySlots serves an empty description: an idle slot, not a failure.
type emptySlots struct{}

func (emptySlots) makeSlot(ctx context.Context, name string) (string, error) { return name, nil }
func (emptySlots) setSlot(ctx context.Context, id, description string, body []byte) error {
	return nil
}
func (emptySlots) readDescription(ctx context.Context, id string) (string, error) { return "", nil }
func (emptySlots) readBody(ctx context.Context, id string) ([]byte, error)        { return nil, nil }

func shrinkStallClocks(t *testing.T) {
	t.Helper()
	// Only the stall timeout is shrunk; readers snapshot it at construction,
	// so lingering goroutines from other tests never read a mutated global.
	oldStall := slotStallTimeout
	slotStallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { slotStallTimeout = oldStall })
}

func TestHeadBodyChecksumMismatchFails(t *testing.T) {
	shrinkStallClocks(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newSlotReader(ctx, badBodySlots{}, slotTable{Slots: []string{"id"}, Watermark: "w"},
		params{concurrency: 1, eagerWindow: 50 * time.Millisecond, maxPollInterval: 5 * time.Millisecond}, nil)
	select {
	case _, ok := <-r.chunks():
		if ok {
			t.Fatal("a mismatched body was delivered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a persistent checksum mismatch retried forever")
	}
	if err := r.Err(); err == nil || !strings.Contains(err.Error(), "no usable body") {
		t.Fatalf("reader ended with %v, want a clear body error", err)
	}
}

func TestEmptySlotStaysIdle(t *testing.T) {
	shrinkStallClocks(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newSlotReader(ctx, emptySlots{}, slotTable{Slots: []string{"id"}, Watermark: "w"},
		params{concurrency: 1, eagerWindow: 50 * time.Millisecond, maxPollInterval: 5 * time.Millisecond}, nil)
	select {
	case <-r.chunks():
		t.Fatal("an empty slot failed the reader instead of staying idle")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
}
