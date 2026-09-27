package exchange

import (
	"context"
	"encoding/json"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

type storageProbeReader struct{ reads atomic.Int32 }

func (r *storageProbeReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 23
	}
	r.reads.Add(1)
	return len(p), nil
}

// This is a retained-storage experiment, not a latency benchmark. Explicit GC
// phases measure pool retention with otherwise unmodified R1/R2 implementations.
func TestAheadRetainedStorageProbe(t *testing.T) {
	const count = 32
	const chunk = 16 * 1024
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	runtime.GC()
	runtime.GC()
	var base, active, joined, firstGC, secondGC, released runtime.MemStats
	runtime.ReadMemStats(&base)
	owners := make([]*Ahead, 0, count)
	readers := make([]*storageProbeReader, 0, count)
	for i := 0; i < count; i++ {
		r := new(storageProbeReader)
		a, err := NewAhead(context.Background(), r, 64*1024)
		if err != nil {
			t.Fatal(err)
		}
		owners = append(owners, a)
		readers = append(readers, r)
	}
	defer func() {
		for _, a := range owners {
			a.Stop()
		}
		for _, a := range owners {
			a.Join()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for _, r := range readers {
		for r.reads.Load() < 6 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if r.reads.Load() != 6 {
			t.Fatalf("unexpected reads: %d", r.reads.Load())
		}
	}
	var queuedBytes int64
	var queuedSlots int
	for _, a := range owners {
		a.mu.Lock()
		queuedBytes += a.size
		queuedSlots += len(a.queue)
		a.mu.Unlock()
	}
	if queuedBytes != count*5*chunk || queuedSlots != count*5 {
		t.Fatalf("pressure bound bytes=%d slots=%d", queuedBytes, queuedSlots)
	}
	runtime.ReadMemStats(&active)
	for _, a := range owners {
		a.Stop()
	}
	for _, a := range owners {
		a.Join()
	}
	var retainedOwnerBytes int64
	for _, a := range owners {
		a.mu.Lock()
		retainedOwnerBytes += a.size
		a.mu.Unlock()
	}
	runtime.ReadMemStats(&joined)
	runtime.GC()
	runtime.ReadMemStats(&firstGC)
	runtime.GC()
	runtime.ReadMemStats(&secondGC)
	runtime.KeepAlive(owners)
	owners = nil
	runtime.GC()
	runtime.ReadMemStats(&released)
	delta := func(v uint64) int64 { return int64(v) - int64(base.HeapAlloc) }
	row := map[string]any{"owners": count, "queue_limit": 64 * 1024, "peak_queued_payload_bytes": queuedBytes, "peak_queue_slots": queuedSlots, "producer_held_payload_bytes": count * chunk, "active_payload_storage_bytes": (queuedSlots + count) * chunk, "owner_retained_payload_after_abort_join": retainedOwnerBytes, "heap_delta_active": delta(active.HeapAlloc), "heap_delta_joined_before_gc": delta(joined.HeapAlloc), "heap_delta_after_gc1_owners_held": delta(firstGC.HeapAlloc), "heap_delta_after_gc2_owners_held": delta(secondGC.HeapAlloc), "heap_delta_after_owner_release_gc": delta(released.HeapAlloc), "heap_scope": "Go HeapAlloc incl owner/runtime metadata; not process RSS"}
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
}
