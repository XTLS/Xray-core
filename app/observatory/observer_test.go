package observatory

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
)

func TestObserverGetObservationSnapshot(t *testing.T) {
	status := &OutboundStatus{
		OutboundTag:  "outbound",
		Alive:        true,
		Delay:        42,
		LastSeenTime: 111,
		LastTryTime:  222,
		HealthPing: &HealthPingMeasurementResult{
			All: 12, Fail: 2, Deviation: 3, Average: 4, Max: 9, Min: 1,
		},
	}
	// Unknown protobuf fields contain mutable byte slices too.
	status.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	status.HealthPing.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x02})
	observer := &Observer{status: []*OutboundStatus{status}}
	read := func() *ObservationResult {
		t.Helper()
		result, err := observer.GetObservation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return result.(*ObservationResult)
	}
	want := proto.Clone(&ObservationResult{Status: observer.status})
	first, second := read(), read()
	if !proto.Equal(first, want) || !proto.Equal(second, want) {
		t.Fatal("GetObservation changed status values")
	}

	first.Status[0].Delay = -1
	first.Status[0].HealthPing.All = -1
	first.Status[0].ProtoReflect().GetUnknown()[2] = 3
	first.Status[0].HealthPing.ProtoReflect().GetUnknown()[2] = 4
	first.Status[0] = &OutboundStatus{OutboundTag: "replaced"}
	if !proto.Equal(read(), want) || !proto.Equal(second, want) {
		t.Fatal("modifying a snapshot changed the observer or another snapshot")
	}

	observer.updateStatusForResult("outbound", &ProbeResult{LastErrorReason: "failed"})
	observer.statusLock.Lock()
	status.HealthPing.All = 100
	status.ProtoReflect().GetUnknown()[2] = 5
	status.HealthPing.ProtoReflect().GetUnknown()[2] = 6
	observer.statusLock.Unlock()
	observer.clearRemovedOutbounds(nil)
	if !proto.Equal(second, want) {
		t.Fatal("updating the observer changed a retained snapshot")
	}
	if len(read().Status) != 0 {
		t.Fatal("expected an empty snapshot after removing all outbounds")
	}
}

func TestObserverGetObservationConcurrent(t *testing.T) {
	observer := &Observer{}
	observer.updateStatusForResult("keep", &ProbeResult{Alive: true, Delay: 42})
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 1000; i++ {
			result := &ProbeResult{Alive: i%2 == 0, Delay: int64(i), LastErrorReason: "failed"}
			observer.updateStatusForResult("keep", result)
			observer.updateStatusForResult("temporary", result)
			observer.clearRemovedOutbounds([]string{"keep"})
		}
	}()
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for i := 0; i < 1000; i++ {
				result, err := observer.GetObservation(context.Background())
				if err != nil {
					t.Error(err)
					return
				}
				data, err := proto.Marshal(result)
				if err != nil {
					t.Error(err)
					return
				}
				var decoded ObservationResult
				if err := proto.Unmarshal(data, &decoded); err != nil {
					t.Error(err)
					return
				}
				if !proto.Equal(result, &decoded) {
					t.Error("protobuf round trip changed the snapshot")
					return
				}
				for _, status := range decoded.Status {
					if status.Alive {
						if status.LastSeenTime != status.LastTryTime || status.LastErrorReason != "" {
							t.Error("inconsistent alive status")
							return
						}
					} else if status.Delay != 99999999 || status.LastErrorReason != "failed" {
						t.Error("inconsistent dead status")
						return
					}
				}
			}
		}()
	}
	close(start)
	workers.Wait()
}

var observationBenchmarkResult proto.Message

func BenchmarkObserverGetObservation(b *testing.B) {
	for _, count := range []int{2, 20, 200} {
		b.Run(fmt.Sprintf("outbounds=%d", count), func(b *testing.B) {
			observer := &Observer{}
			for i := 0; i < count; i++ {
				observer.updateStatusForResult(fmt.Sprintf("outbound-%d", i), &ProbeResult{Alive: true, Delay: 42})
			}
			ctx := context.Background()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := observer.GetObservation(ctx)
				if err != nil {
					b.Fatal(err)
				}
				observationBenchmarkResult = result
			}
		})
	}
}

func TestObserverUpdateStatusPrunesStaleOutbounds(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{
				OutboundTag:     "keep",
				Alive:           true,
				Delay:           42,
				LastErrorReason: "",
				LastSeenTime:    111,
				LastTryTime:     222,
			},
			{
				OutboundTag:     "drop",
				Alive:           false,
				Delay:           99999999,
				LastErrorReason: "probe failed",
				LastSeenTime:    333,
				LastTryTime:     444,
			},
		},
	}

	observer.clearRemovedOutbounds([]string{"keep"})

	if len(observer.status) != 1 {
		t.Fatalf("expected 1 status after pruning, got %d", len(observer.status))
	}

	got := observer.status[0]
	if got.OutboundTag != "keep" {
		t.Fatalf("expected remaining status for keep, got %q", got.OutboundTag)
	}
	if !got.Alive {
		t.Fatal("expected remaining status to preserve Alive field")
	}
	if got.Delay != 42 {
		t.Fatalf("expected remaining status to preserve Delay, got %d", got.Delay)
	}
	if got.LastSeenTime != 111 {
		t.Fatalf("expected remaining status to preserve LastSeenTime, got %d", got.LastSeenTime)
	}
	if got.LastTryTime != 222 {
		t.Fatalf("expected remaining status to preserve LastTryTime, got %d", got.LastTryTime)
	}
}

func TestObserverUpdateStatusClearsWhenNoOutboundsRemain(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{OutboundTag: "drop-1"},
			{OutboundTag: "drop-2"},
		},
	}

	observer.clearRemovedOutbounds(nil)

	if len(observer.status) != 0 {
		t.Fatalf("expected all statuses to be removed, got %d", len(observer.status))
	}
}
