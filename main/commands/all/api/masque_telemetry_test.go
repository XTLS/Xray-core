package api

import (
	"strings"
	"testing"
)

func TestNormalizeMasqueTelemetrySortMode(t *testing.T) {
	got, err := normalizeMasqueTelemetrySortMode("score")
	if err != nil {
		t.Fatal(err)
	}
	if got != masqueSortScore {
		t.Fatalf("unexpected sort mode: %q", got)
	}
}

func TestNormalizeMasqueTelemetrySortModeRejectsInvalid(t *testing.T) {
	if _, err := normalizeMasqueTelemetrySortMode("weird"); err == nil {
		t.Fatal("expected invalid sort mode error")
	}
}

func TestNormalizeMasqueTelemetryOnlyVerdict(t *testing.T) {
	got, err := normalizeMasqueTelemetryOnlyVerdict("fallback-heavy")
	if err != nil {
		t.Fatal(err)
	}
	if got != "fallback-heavy" {
		t.Fatalf("unexpected verdict filter: %q", got)
	}
}

func TestNormalizeMasqueTelemetryOnlyVerdictRejectsInvalid(t *testing.T) {
	if _, err := normalizeMasqueTelemetryOnlyVerdict("bad"); err == nil {
		t.Fatal("expected invalid verdict filter error")
	}
}

func TestResolveMetricsDebugVarsURLAddsDefaults(t *testing.T) {
	got, err := resolveMetricsDebugVarsURL("127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://127.0.0.1:8080/debug/vars" {
		t.Fatalf("unexpected url: %q", got)
	}
}

func TestResolveMetricsDebugVarsURLPreservesExplicitPath(t *testing.T) {
	got, err := resolveMetricsDebugVarsURL("https://example.com/custom/vars")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.com/custom/vars" {
		t.Fatalf("unexpected url: %q", got)
	}
}

func TestFilterMasqueTelemetryByTag(t *testing.T) {
	snapshot := &masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 2,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {"requested_sessions": 1},
			"proxy-b": {"requested_sessions": 1},
		},
	}

	filtered, err := filterMasqueTelemetry(snapshot, "proxy-b")
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Outbound) != 1 {
		t.Fatalf("expected 1 outbound bucket, got %d", len(filtered.Outbound))
	}
	if filtered.Outbound["proxy-b"]["requested_sessions"] != 1 {
		t.Fatalf("unexpected filtered value: %#v", filtered.Outbound["proxy-b"])
	}
}

func TestFilterMasqueTelemetryByMissingTagReturnsError(t *testing.T) {
	snapshot := &masqueTelemetrySnapshot{
		Global: map[string]int64{},
		Outbound: map[string]map[string]int64{
			"proxy-a": {"requested_sessions": 1},
		},
	}

	if _, err := filterMasqueTelemetry(snapshot, "missing"); err == nil {
		t.Fatal("expected missing tag error")
	}
}

func TestFilterMasqueTelemetryByVerdict(t *testing.T) {
	snapshot := &masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 3,
		},
		Outbound: map[string]map[string]int64{
			"healthy-a": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 10,
			},
			"degraded-a": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 9,
				"read_fallback_sessions":          1,
			},
			"fallback-a": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 3,
				"read_fallback_sessions":          4,
				"write_fallback_sessions":         3,
			},
		},
	}

	degraded := filterMasqueTelemetryByVerdict(snapshot, "degraded")
	if len(degraded.Outbound) != 1 {
		t.Fatalf("expected 1 degraded outbound, got %d", len(degraded.Outbound))
	}
	if _, ok := degraded.Outbound["degraded-a"]; !ok {
		t.Fatalf("expected degraded-a, got %#v", degraded.Outbound)
	}

	fallbackHeavy := filterMasqueTelemetryByVerdict(snapshot, "fallback-heavy")
	if len(fallbackHeavy.Outbound) != 1 {
		t.Fatalf("expected 1 fallback-heavy outbound, got %d", len(fallbackHeavy.Outbound))
	}
	if _, ok := fallbackHeavy.Outbound["fallback-a"]; !ok {
		t.Fatalf("expected fallback-a, got %#v", fallbackHeavy.Outbound)
	}
}

func TestRenderMasqueTelemetryText(t *testing.T) {
	output := renderMasqueTelemetryText(&masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions":              3,
			"bidirectional_datagram_sessions": 2,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {
				"requested_sessions": 2,
			},
			"_unscoped": {
				"requested_sessions": 1,
			},
		},
	}, masqueTelemetryRenderOptions{sortMode: masqueSortName})

	for _, fragment := range []string{
		"Global:",
		"bidirectional_datagram_sessions: 2",
		"health_score: 80",
		"fallback_total: 0",
		"requested_sessions: 3",
		"Outbound _unscoped [degraded]:",
		"Outbound proxy-a [degraded]:",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected output to contain %q, got:\n%s", fragment, output)
		}
	}
}

func TestMasqueTelemetryHealthScore(t *testing.T) {
	score := masqueTelemetryHealthScore(map[string]int64{
		"requested_sessions":              10,
		"bidirectional_datagram_sessions": 9,
		"read_fallback_sessions":          1,
		"write_fallback_sessions":         0,
	})
	if score != 94 {
		t.Fatalf("unexpected health score: %d", score)
	}
}

func TestMasqueTelemetryVerdict(t *testing.T) {
	testCases := []struct {
		name     string
		metrics  map[string]int64
		expected string
	}{
		{
			name: "idle",
			metrics: map[string]int64{
				"requested_sessions": 0,
			},
			expected: "idle",
		},
		{
			name: "healthy",
			metrics: map[string]int64{
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 10,
				"read_fallback_sessions":          0,
				"write_fallback_sessions":         0,
			},
			expected: "healthy",
		},
		{
			name: "degraded",
			metrics: map[string]int64{
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 9,
				"read_fallback_sessions":          1,
				"write_fallback_sessions":         0,
			},
			expected: "degraded",
		},
		{
			name: "fallback-heavy",
			metrics: map[string]int64{
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 3,
				"read_fallback_sessions":          4,
				"write_fallback_sessions":         3,
			},
			expected: "fallback-heavy",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := masqueTelemetryVerdict(tc.metrics)
			if got != tc.expected {
				t.Fatalf("unexpected verdict: got %q want %q", got, tc.expected)
			}
		})
	}
}

func TestRenderMasqueTelemetryTextSortsByFallbackAndLimits(t *testing.T) {
	output := renderMasqueTelemetryText(&masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 3,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {
				"requested_sessions":      2,
				"read_fallback_sessions":  1,
				"write_fallback_sessions": 0,
			},
			"proxy-b": {
				"requested_sessions":      2,
				"read_fallback_sessions":  2,
				"write_fallback_sessions": 1,
			},
			"proxy-c": {
				"requested_sessions":      2,
				"read_fallback_sessions":  0,
				"write_fallback_sessions": 0,
			},
		},
	}, masqueTelemetryRenderOptions{
		sortMode: masqueSortFallback,
		limit:    2,
	})

	first := strings.Index(output, "Outbound proxy-b [fallback=3 fallback-heavy]:")
	second := strings.Index(output, "Outbound proxy-a [fallback=1 degraded]:")
	third := strings.Index(output, "Outbound proxy-c")
	if first == -1 || second == -1 {
		t.Fatalf("expected fallback-sorted output, got:\n%s", output)
	}
	if !(first < second) {
		t.Fatalf("expected proxy-b before proxy-a, got:\n%s", output)
	}
	if third != -1 {
		t.Fatalf("expected limit to exclude proxy-c, got:\n%s", output)
	}
}

func TestRenderMasqueTelemetryTextSortsByScoreWorstFirst(t *testing.T) {
	output := renderMasqueTelemetryText(&masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 3,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 9,
				"read_fallback_sessions":          1,
				"write_fallback_sessions":         0,
			},
			"proxy-b": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 3,
				"read_fallback_sessions":          4,
				"write_fallback_sessions":         3,
			},
			"proxy-c": {
				"requested_sessions":              10,
				"bidirectional_datagram_sessions": 10,
				"read_fallback_sessions":          0,
				"write_fallback_sessions":         0,
			},
		},
	}, masqueTelemetryRenderOptions{
		sortMode: masqueSortScore,
	})

	first := strings.Index(output, "Outbound proxy-b [score=58 fallback-heavy]:")
	second := strings.Index(output, "Outbound proxy-a [score=94 degraded]:")
	third := strings.Index(output, "Outbound proxy-c [score=100 healthy]:")
	if first == -1 || second == -1 || third == -1 {
		t.Fatalf("expected score-sorted output, got:\n%s", output)
	}
	if !(first < second && second < third) {
		t.Fatalf("expected proxy-b before proxy-a before proxy-c, got:\n%s", output)
	}
}

func TestRenderMasqueTelemetryJSON(t *testing.T) {
	output, err := renderMasqueTelemetryJSON(&masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 1,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {
				"requested_sessions": 1,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, fragment := range []string{
		"\"global\"",
		"\"outbound\"",
		"\"proxy-a\"",
		"\"requested_sessions\": 1",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected json output to contain %q, got:\n%s", fragment, output)
		}
	}
}

func TestLimitMasqueTelemetrySnapshotUsesTopSelection(t *testing.T) {
	snapshot := limitMasqueTelemetrySnapshot(&masqueTelemetrySnapshot{
		Global: map[string]int64{
			"requested_sessions": 3,
		},
		Outbound: map[string]map[string]int64{
			"proxy-a": {
				"requested_sessions": 1,
			},
			"proxy-b": {
				"requested_sessions": 3,
			},
			"proxy-c": {
				"requested_sessions": 2,
			},
		},
	}, masqueTelemetryRenderOptions{
		sortMode: masqueSortRequested,
		limit:    2,
	})

	if len(snapshot.Outbound) != 2 {
		t.Fatalf("expected 2 outbound buckets, got %d", len(snapshot.Outbound))
	}
	if _, ok := snapshot.Outbound["proxy-b"]; !ok {
		t.Fatalf("expected proxy-b in limited snapshot: %#v", snapshot.Outbound)
	}
	if _, ok := snapshot.Outbound["proxy-c"]; !ok {
		t.Fatalf("expected proxy-c in limited snapshot: %#v", snapshot.Outbound)
	}
	if _, ok := snapshot.Outbound["proxy-a"]; ok {
		t.Fatalf("did not expect proxy-a in limited snapshot: %#v", snapshot.Outbound)
	}
}
