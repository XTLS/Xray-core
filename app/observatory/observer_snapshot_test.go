package observatory

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"
)

func observationSnapshot(t *testing.T, observer *Observer) *ObservationResult {
	t.Helper()
	result, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return result.(*ObservationResult)
}

func TestObservationSnapshotIsolation(t *testing.T) {
	observer := &Observer{status: []*OutboundStatus{
		{
			OutboundTag: "keep", Alive: true, Delay: 42, LastTryTime: 123, LastSeenTime: 123,
			HealthPing: &HealthPingMeasurementResult{All: 3, Average: 42},
		},
		{OutboundTag: "drop", LastErrorReason: "probe failed"},
	}}
	expected := proto.Clone(&ObservationResult{Status: observer.status})
	snapshot := observationSnapshot(t, observer)
	if !proto.Equal(snapshot, expected) {
		t.Fatal("snapshot does not preserve observation fields")
	}

	observer.updateStatusForResult("keep", &ProbeResult{Alive: false, LastErrorReason: "offline"})
	observer.updateStatusForResult("new", &ProbeResult{Alive: true, Delay: 10})
	observer.clearRemovedOutbounds([]string{"keep", "new"})
	if !proto.Equal(snapshot, expected) {
		t.Fatal("updating or pruning the observer changed an existing snapshot")
	}

	current := observationSnapshot(t, observer)
	wantCurrent := proto.Clone(current)
	snapshot.Status[0].HealthPing.All = 999
	current.Status[0].Delay = 999
	current.Status[0].HealthPing.Average = 999
	current.Status[1] = &OutboundStatus{OutboundTag: "replaced"}
	if !proto.Equal(observationSnapshot(t, observer), wantCurrent) {
		t.Fatal("mutating a returned snapshot changed observer state")
	}
}

func TestObservationSnapshotEmpty(t *testing.T) {
	observer := new(Observer)
	if got := observationSnapshot(t, observer); len(got.Status) != 0 {
		t.Fatalf("empty observer returned %v", got)
	}
	observer.updateStatusForResult("test", &ProbeResult{Alive: true})
	snapshot := observationSnapshot(t, observer)
	observer.clearRemovedOutbounds(nil)
	if len(observationSnapshot(t, observer).Status) != 0 || len(snapshot.Status) != 1 {
		t.Fatal("pruning should empty the observer without changing its snapshot")
	}
}

func TestObservationSnapshotConcurrent(t *testing.T) {
	observer := new(Observer)
	var workers sync.WaitGroup
	start := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for i := range 500 {
			observer.updateStatusForResult("keep", &ProbeResult{Alive: true, Delay: int64(i)})
			observer.updateStatusForResult("drop", &ProbeResult{Alive: false, LastErrorReason: "offline"})
			observer.clearRemovedOutbounds([]string{"keep"})
		}
	}()
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 500 {
				snapshot := observationSnapshot(t, observer)
				// gRPC serializes the result after GetObservation has returned.
				if _, err := proto.Marshal(snapshot); err != nil {
					t.Error(err)
				}
				for _, status := range snapshot.Status {
					status.LastErrorReason = "caller-owned copy"
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	result := observationSnapshot(t, observer)
	if len(result.Status) != 1 || !result.Status[0].Alive || result.Status[0].LastErrorReason != "" {
		t.Fatalf("unexpected final observation: %v", result)
	}
}
