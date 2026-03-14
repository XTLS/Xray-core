package burst

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
)

func TestStartSchedulerRunsInitialCheckOnlyOnceBeforeFirstTick(t *testing.T) {
	started := make(chan struct{}, 2)
	hp := &HealthPing{
		ctx: context.Background(),
		Settings: &HealthPingSettings{
			Interval:      50 * time.Millisecond,
			SamplingCount: 1,
		},
	}
	hp.batchCheck = func(tags []string, duration time.Duration, rounds int) {
		started <- struct{}{}
	}

	hp.StartScheduler(func() ([]string, error) {
		return []string{"node-a"}, nil
	}, nil)
	defer hp.StopScheduler()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("expected initial health check to run")
	}

	select {
	case <-started:
		t.Fatal("expected only one health check before the first ticker interval")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestStartSchedulerDoesNotOverlapScheduledWaves(t *testing.T) {
	var calls atomic.Int32
	var active atomic.Int32
	var maxActive atomic.Int32

	hp := &HealthPing{
		ctx: context.Background(),
		Settings: &HealthPingSettings{
			Interval:      10 * time.Millisecond,
			SamplingCount: 1,
		},
	}
	hp.batchCheck = func(tags []string, duration time.Duration, rounds int) {
		calls.Add(1)
		current := active.Add(1)
		for {
			recorded := maxActive.Load()
			if current <= recorded || maxActive.CompareAndSwap(recorded, current) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		active.Add(-1)
	}

	hp.StartScheduler(func() ([]string, error) {
		return []string{"node-a"}, nil
	}, nil)
	time.Sleep(120 * time.Millisecond)
	hp.StopScheduler()

	if calls.Load() < 2 {
		t.Fatalf("expected multiple health-check waves, got %d", calls.Load())
	}
	if maxActive.Load() != 1 {
		t.Fatalf("expected serial scheduler execution, got max overlap %d", maxActive.Load())
	}
}

func TestSampleDelaysUseOneProbePerSlot(t *testing.T) {
	hp := &HealthPing{
		ctx: context.Background(),
		Settings: &HealthPingSettings{
			Interval:      10 * time.Second,
			SamplingCount: 4,
		},
	}

	delays := hp.sampleDelays(40*time.Second, 4)
	if len(delays) != 4 {
		t.Fatalf("expected 4 scheduled delays, got %d", len(delays))
	}

	slot := 10 * time.Second
	for i, delay := range delays {
		slotStart := time.Duration(i) * slot
		slotEnd := slotStart + slot
		if delay < slotStart || delay >= slotEnd {
			t.Fatalf("expected delay %s to stay within slot [%s, %s), got %s", delay, slotStart, slotEnd, delay)
		}
	}
}

func TestRefreshSnapshotTracksCleanupAndSorting(t *testing.T) {
	resultA := NewHealthPingResult(2, time.Hour)
	resultA.Put(20 * time.Millisecond)
	resultB := NewHealthPingResult(2, time.Hour)
	resultB.Put(40 * time.Millisecond)

	observer := &Observer{
		hp: &HealthPing{
			Results: map[string]*HealthPingRTTS{
				"node-b": resultB,
				"node-a": resultA,
			},
		},
	}

	observer.refreshSnapshot()
	response, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal("expected initial observation snapshot:", err)
	}
	result := response.(*observatory.ObservationResult)
	if len(result.Status) != 2 {
		t.Fatalf("expected 2 statuses, got %d", len(result.Status))
	}
	if result.Status[0].OutboundTag != "node-a" || result.Status[1].OutboundTag != "node-b" {
		t.Fatalf("expected sorted snapshot, got %v", []string{result.Status[0].OutboundTag, result.Status[1].OutboundTag})
	}

	observer.hp.Cleanup([]string{"node-b"})
	observer.refreshSnapshot()
	response, err = observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal("expected refreshed observation snapshot:", err)
	}
	result = response.(*observatory.ObservationResult)
	if len(result.Status) != 1 {
		t.Fatalf("expected 1 status after cleanup, got %d", len(result.Status))
	}
	if result.Status[0].OutboundTag != "node-b" {
		t.Fatalf("expected remaining status to be node-b, got %q", result.Status[0].OutboundTag)
	}
}

func TestRefreshSnapshotTracksLastTryAndLastSeenTimes(t *testing.T) {
	result := NewHealthPingResult(2, time.Hour)
	result.Put(20 * time.Millisecond)
	result.rtts[result.idx].time = time.Unix(100, 0)
	result.Put(rttFailed)
	result.rtts[result.idx].time = time.Unix(200, 0)

	observer := &Observer{
		hp: &HealthPing{
			Results: map[string]*HealthPingRTTS{
				"node-a": result,
			},
		},
	}

	observer.refreshSnapshot()
	response, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatal("expected observation snapshot:", err)
	}
	statuses := response.(*observatory.ObservationResult).Status
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0].LastTryTime != 200 {
		t.Fatalf("expected LastTryTime to reflect the newest probe, got %d", statuses[0].LastTryTime)
	}
	if statuses[0].LastSeenTime != 100 {
		t.Fatalf("expected LastSeenTime to reflect the newest successful probe, got %d", statuses[0].LastSeenTime)
	}
}
