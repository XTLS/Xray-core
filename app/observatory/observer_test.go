package observatory

import (
	"context"
	"testing"
)

func TestGetObservationReturnsSnapshot(t *testing.T) {
	t.Parallel()

	observer := &Observer{
		status: []*OutboundStatus{
			{
				OutboundTag: "old",
				Alive:       true,
				Delay:       10,
			},
		},
	}

	msg, err := observer.GetObservation(context.Background())
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}

	result := msg.(*ObservationResult)
	if len(result.Status) != 1 {
		t.Fatalf("unexpected status len: got %d, want 1", len(result.Status))
	}
	if result.Status[0] == observer.status[0] {
		t.Fatal("GetObservation() returned internal status pointer")
	}

	result.Status[0].Alive = false
	if !observer.status[0].Alive {
		t.Fatal("mutating observation result must not mutate internal status")
	}
}

func TestUpdateStatusRemovesStaleOutbounds(t *testing.T) {
	t.Parallel()

	observer := &Observer{
		status: []*OutboundStatus{
			{OutboundTag: "a"},
			{OutboundTag: "b"},
			{OutboundTag: "c"},
		},
	}

	observer.updateStatus([]string{"b", "d"})

	if len(observer.status) != 1 {
		t.Fatalf("unexpected status len after cleanup: got %d, want 1", len(observer.status))
	}
	if observer.status[0].OutboundTag != "b" {
		t.Fatalf("unexpected remaining outbound: got %q, want %q", observer.status[0].OutboundTag, "b")
	}
}
