package observatory

import (
	"context"
	"sync"
	"testing"
)

func TestBuildStatusSnapshotPrunesRemovedOutbounds(t *testing.T) {
	observer := &Observer{
		config: &Config{},
		probeFunc: func(tag string) ProbeResult {
			return ProbeResult{Alive: true, Delay: 10}
		},
	}
	observer.setStatusSnapshot([]*OutboundStatus{
		{OutboundTag: "node-a", Alive: true, LastSeenTime: 100},
		{OutboundTag: "node-b", Alive: true, LastSeenTime: 200},
	})

	statuses, completed := observer.buildStatusSnapshot([]string{"node-b"}, 0)
	if !completed {
		t.Fatal("expected snapshot build to complete")
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status after pruning removed outbounds, got %d", len(statuses))
	}
	if statuses[0].OutboundTag != "node-b" {
		t.Fatalf("expected remaining outbound to be node-b, got %q", statuses[0].OutboundTag)
	}
}

func TestGetObservationReturnsStableCopiesWhileSnapshotsUpdate(t *testing.T) {
	observer := &Observer{
		config: &Config{},
	}
	observer.setStatusSnapshot([]*OutboundStatus{
		{OutboundTag: "node-a", Alive: true, LastSeenTime: 100},
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			observer.setStatusSnapshot([]*OutboundStatus{
				{OutboundTag: "node-a", Alive: i%2 == 0, LastSeenTime: int64(100 + i)},
			})
		}
	}()

	for i := 0; i < 100; i++ {
		response, err := observer.GetObservation(context.Background())
		if err != nil {
			t.Fatal("expected observation snapshot:", err)
		}
		result := response.(*ObservationResult)
		if len(result.Status) == 0 {
			t.Fatal("expected status snapshot to contain an outbound")
		}
		result.Status[0].Alive = false
		result.Status[0].LastSeenTime = 0
	}

	wg.Wait()

	response, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal("expected final observation snapshot:", err)
	}
	result := response.(*ObservationResult)
	if len(result.Status) != 1 {
		t.Fatalf("expected 1 outbound in final snapshot, got %d", len(result.Status))
	}
	if result.Status[0].OutboundTag != "node-a" {
		t.Fatalf("expected final snapshot to keep node-a, got %q", result.Status[0].OutboundTag)
	}
	if result.Status[0].LastSeenTime == 0 {
		t.Fatal("expected internal snapshot to remain intact after caller mutation")
	}
}

func TestFailedProbePreservesLastSeenTime(t *testing.T) {
	observer := &Observer{
		config: &Config{},
		probeFunc: func(tag string) ProbeResult {
			return ProbeResult{Alive: false, LastErrorReason: "probe failed"}
		},
	}
	observer.setStatusSnapshot([]*OutboundStatus{
		{OutboundTag: "node-a", Alive: true, LastSeenTime: 12345},
	})

	statuses, completed := observer.buildStatusSnapshot([]string{"node-a"}, 0)
	if !completed {
		t.Fatal("expected snapshot build to complete")
	}
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].LastSeenTime != 12345 {
		t.Fatalf("expected LastSeenTime to be preserved, got %d", statuses[0].LastSeenTime)
	}
	if statuses[0].Delay != 99999999 {
		t.Fatalf("expected failed probes to use sentinel delay, got %d", statuses[0].Delay)
	}
}
