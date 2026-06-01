package router

import (
	"testing"

	"github.com/xtls/xray-core/app/observatory"
)

func leastPingStatus(tag string, alive bool, delayMs int64, hp *observatory.HealthPingMeasurementResult) *observatory.OutboundStatus {
	return &observatory.OutboundStatus{
		OutboundTag: tag,
		Alive:       alive,
		Delay:       delayMs,
		HealthPing:  hp,
	}
}

func leastPingHealth(all, fail, deviation int64) *observatory.HealthPingMeasurementResult {
	return &observatory.HealthPingMeasurementResult{All: all, Fail: fail, Deviation: deviation}
}

func TestPickLeastPing(t *testing.T) {
	cases := []struct {
		name       string
		status     []*observatory.OutboundStatus
		candidates []string
		expected   string
	}{
		{
			// Regression guard: with healthy outbounds and no health stats the
			// selection is unchanged — the lowest Delay still wins.
			name: "lowest delay wins when all healthy",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 50, nil),
				leastPingStatus("b", true, 20, nil),
				leastPingStatus("c", true, 80, nil),
			},
			candidates: []string{"a", "b", "c"},
			expected:   "b",
		},
		{
			// Core fix: a 20ms tunnel that fails 9/10 probes must lose to a
			// slower but reliable one, because its low Delay is only the average
			// of the few successful probes.
			name: "reject fast but flaky node",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 20, leastPingHealth(10, 9, 0)),
				leastPingStatus("b", true, 60, leastPingHealth(10, 0, 0)),
			},
			candidates: []string{"a", "b"},
			expected:   "b",
		},
		{
			// Backward compatibility with the plain observer, which leaves
			// HealthPing nil: selection is by Delay only.
			name: "nil health ping falls back to pure delay",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 20, nil),
				leastPingStatus("b", true, 50, nil),
			},
			candidates: []string{"a", "b"},
			expected:   "a",
		},
		{
			name: "equal delay broken by lower deviation",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 30, leastPingHealth(10, 0, 20)),
				leastPingStatus("b", true, 30, leastPingHealth(10, 0, 5)),
			},
			candidates: []string{"a", "b"},
			expected:   "b",
		},
		{
			// When every candidate is flaky, never return worse than the old
			// behavior: fall back to the lowest-Delay alive outbound.
			name: "all flaky falls back to lowest delay",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 20, leastPingHealth(10, 9, 0)),
				leastPingStatus("b", true, 50, leastPingHealth(10, 8, 0)),
			},
			candidates: []string{"a", "b"},
			expected:   "a",
		},
		{
			name: "skips dead and non-candidate outbounds",
			status: []*observatory.OutboundStatus{
				leastPingStatus("dead", false, 5, nil),
				leastPingStatus("other", true, 1, nil),
				leastPingStatus("a", true, 40, nil),
			},
			candidates: []string{"a", "dead"},
			expected:   "a",
		},
		{
			name: "empty when nothing qualifies",
			status: []*observatory.OutboundStatus{
				leastPingStatus("a", true, 10, nil),
			},
			candidates: []string{"x"},
			expected:   "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pickLeastPing(c.status, c.candidates); got != c.expected {
				t.Errorf("pickLeastPing() = %q, want %q", got, c.expected)
			}
		})
	}
}
