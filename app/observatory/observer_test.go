package observatory

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/features/extension"
)

func TestGetObservationReturnsSortedSnapshot(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{
				OutboundTag: "z-out",
				Delay:       50,
				HealthPing: &HealthPingMeasurementResult{
					Average: 50,
				},
			},
			{
				OutboundTag: "a-out",
				Delay:       10,
				HealthPing: &HealthPingMeasurementResult{
					Average: 10,
				},
			},
		},
	}

	msg, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatalf("GetObservation returned error: %v", err)
	}

	result, ok := msg.(*ObservationResult)
	if !ok {
		t.Fatalf("GetObservation returned %T, want *ObservationResult", msg)
	}

	if len(result.Status) != 2 {
		t.Fatalf("unexpected snapshot size: got %d, want 2", len(result.Status))
	}
	if got := result.Status[0].OutboundTag; got != "a-out" {
		t.Fatalf("unexpected first tag: got %q, want %q", got, "a-out")
	}
	if got := result.Status[1].OutboundTag; got != "z-out" {
		t.Fatalf("unexpected second tag: got %q, want %q", got, "z-out")
	}

	result.Status[0].Delay = 999
	result.Status[0].HealthPing.Average = 999

	if observer.status[1].Delay != 10 {
		t.Fatalf("internal delay was modified through snapshot: got %d, want 10", observer.status[1].Delay)
	}
	if observer.status[1].HealthPing.Average != 10 {
		t.Fatalf("internal health ping was modified through snapshot: got %d, want 10", observer.status[1].HealthPing.Average)
	}
}

func TestUpdateStatusRemovesStaleOutbounds(t *testing.T) {
	observer := &Observer{
		status: []*OutboundStatus{
			{OutboundTag: "keep-b"},
			{OutboundTag: "remove-me"},
			{OutboundTag: "keep-a"},
		},
	}

	observer.updateStatus([]string{"keep-a", "keep-b"})

	if len(observer.status) != 2 {
		t.Fatalf("unexpected status size after cleanup: got %d, want 2", len(observer.status))
	}

	msg, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatalf("GetObservation returned error: %v", err)
	}

	result := msg.(*ObservationResult)
	if len(result.Status) != 2 {
		t.Fatalf("unexpected snapshot size after cleanup: got %d, want 2", len(result.Status))
	}
	if result.Status[0].OutboundTag != "keep-a" || result.Status[1].OutboundTag != "keep-b" {
		t.Fatalf("unexpected tags after cleanup: got %q, %q", result.Status[0].OutboundTag, result.Status[1].OutboundTag)
	}

	observer.updateStatus(nil)
	if len(observer.status) != 0 {
		t.Fatalf("expected all statuses to be removed, got %d", len(observer.status))
	}
}

func TestGetOutboundECHStatusReturnsSnapshotAndCleanup(t *testing.T) {
	observer := &Observer{
		echStatus: map[string]extension.ECHStatus{
			"keep": {
				Enabled:      true,
				Accepted:     true,
				ServerName:   "keep.example",
				LastTryTime:  100,
				LastSeenTime: 100,
			},
			"drop": {
				Enabled:     true,
				Accepted:    false,
				LastTryTime: 90,
			},
		},
	}

	snapshot, err := observer.GetOutboundECHStatus(context.Background())
	if err != nil {
		t.Fatalf("GetOutboundECHStatus returned error: %v", err)
	}
	if len(snapshot) != 2 {
		t.Fatalf("unexpected ech snapshot size: got %d, want 2", len(snapshot))
	}

	snapshot["keep"] = extension.ECHStatus{}
	if !observer.echStatus["keep"].Accepted {
		t.Fatal("internal ech status was modified through snapshot")
	}

	observer.updateStatus([]string{"keep"})
	if _, ok := observer.echStatus["drop"]; ok {
		t.Fatal("stale ech status was not removed during cleanup")
	}
}

func TestUpdateStatusForResultTracksECHAcceptance(t *testing.T) {
	observer := &Observer{}
	result := &ProbeResult{Alive: true, Delay: 15}
	observer.updateStatusForResult("ech-out", result, extension.ECHStatus{
		Enabled:    true,
		Accepted:   true,
		ServerName: "cdn.example",
	})

	status, err := observer.GetOutboundECHStatus(context.Background())
	if err != nil {
		t.Fatalf("GetOutboundECHStatus returned error: %v", err)
	}
	got := status["ech-out"]
	if !got.Enabled || !got.Accepted {
		t.Fatalf("unexpected ech status after success: %+v", got)
	}
	if got.ServerName != "cdn.example" {
		t.Fatalf("unexpected ech server name: got %q, want %q", got.ServerName, "cdn.example")
	}
	if got.LastSeenTime == 0 || got.LastTryTime == 0 {
		t.Fatalf("expected ech timestamps to be populated, got %+v", got)
	}

	observer.updateStatusForResult("ech-out", &ProbeResult{Alive: false, LastErrorReason: "failed"}, extension.ECHStatus{
		Enabled:    true,
		Accepted:   true,
		ServerName: "cdn.example",
	})
	status, _ = observer.GetOutboundECHStatus(context.Background())
	if status["ech-out"].Accepted {
		t.Fatalf("expected ech acceptance to reset after failed probe, got %+v", status["ech-out"])
	}
}
