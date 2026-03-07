package burst

import (
	"context"
	"testing"
	"time"
)

func TestNewHealthPingIntervalBounds(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		inputInterval time.Duration
		wantInterval  time.Duration
	}{
		{
			name:          "default interval",
			inputInterval: 0,
			wantInterval:  time.Minute,
		},
		{
			name:          "below min interval",
			inputInterval: 9 * time.Second,
			wantInterval:  10 * time.Second,
		},
		{
			name:          "at min interval",
			inputInterval: 10 * time.Second,
			wantInterval:  10 * time.Second,
		},
		{
			name:          "above min interval",
			inputInterval: 11 * time.Second,
			wantInterval:  11 * time.Second,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			hp := NewHealthPing(context.Background(), nil, &HealthPingConfig{
				Interval: int64(tc.inputInterval),
			})

			if got := hp.Settings.Interval; got != tc.wantInterval {
				t.Fatalf("unexpected interval: got %s, want %s", got, tc.wantInterval)
			}
		})
	}
}
