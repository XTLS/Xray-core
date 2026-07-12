package burst

import (
	"context"
	"testing"
	"time"
)

func TestHealthPingNotifiesAfterResultUpdate(t *testing.T) {
	healthPing := NewHealthPing(context.Background(), nil, nil)
	updates := 0
	healthPing.onUpdate = func() { updates++ }

	healthPing.PutResult("proxy-a", 42*time.Millisecond)

	if updates != 1 {
		t.Fatalf("updates = %d, want 1", updates)
	}
}

func TestBurstObserverReportsConfiguredProbeDeadline(t *testing.T) {
	observer := &Observer{hp: &HealthPing{Settings: &HealthPingSettings{Timeout: 30 * time.Second}}}
	if got, want := observer.ObservationProbeDeadline(), 30*time.Second; got != want {
		t.Fatalf("probe deadline = %v, want %v", got, want)
	}

	observer.hp.Settings.Connectivity = "https://example.com/generate_204"
	if got, want := observer.ObservationProbeDeadline(), 60*time.Second; got != want {
		t.Fatalf("probe deadline with connectivity check = %v, want %v", got, want)
	}
}
