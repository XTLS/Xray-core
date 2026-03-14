package router

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/observatory"
	"google.golang.org/protobuf/proto"
)

/*
Split into multiple package, need to be tested separately

	func TestSelectLeastLoad(t *testing.T) {
		settings := &StrategyLeastLoadConfig{
			HealthCheck: &HealthPingConfig{
				SamplingCount: 10,
			},
			Expected: 1,
			MaxRTT:   int64(time.Millisecond * time.Duration(800)),
		}
		strategy := NewLeastLoadStrategy(settings)
		// std 40
		strategy.PutResult("a", time.Millisecond*time.Duration(60))
		strategy.PutResult("a", time.Millisecond*time.Duration(140))
		strategy.PutResult("a", time.Millisecond*time.Duration(60))
		strategy.PutResult("a", time.Millisecond*time.Duration(140))
		// std 60
		strategy.PutResult("b", time.Millisecond*time.Duration(40))
		strategy.PutResult("b", time.Millisecond*time.Duration(160))
		strategy.PutResult("b", time.Millisecond*time.Duration(40))
		strategy.PutResult("b", time.Millisecond*time.Duration(160))
		// std 0, but >MaxRTT
		strategy.PutResult("c", time.Millisecond*time.Duration(1000))
		strategy.PutResult("c", time.Millisecond*time.Duration(1000))
		strategy.PutResult("c", time.Millisecond*time.Duration(1000))
		strategy.PutResult("c", time.Millisecond*time.Duration(1000))
		expected := "a"
		actual := strategy.SelectAndPick([]string{"a", "b", "c", "untested"})
		if actual != expected {
			t.Errorf("expected: %v, actual: %v", expected, actual)
		}
	}

	func TestSelectLeastLoadWithCost(t *testing.T) {
		settings := &StrategyLeastLoadConfig{
			HealthCheck: &HealthPingConfig{
				SamplingCount: 10,
			},
			Costs: []*StrategyWeight{
				{Match: "a", Value: 9},
			},
			Expected: 1,
		}
		strategy := NewLeastLoadStrategy(settings, nil)
		// std 40, std+c 120
		strategy.PutResult("a", time.Millisecond*time.Duration(60))
		strategy.PutResult("a", time.Millisecond*time.Duration(140))
		strategy.PutResult("a", time.Millisecond*time.Duration(60))
		strategy.PutResult("a", time.Millisecond*time.Duration(140))
		// std 60
		strategy.PutResult("b", time.Millisecond*time.Duration(40))
		strategy.PutResult("b", time.Millisecond*time.Duration(160))
		strategy.PutResult("b", time.Millisecond*time.Duration(40))
		strategy.PutResult("b", time.Millisecond*time.Duration(160))
		expected := "b"
		actual := strategy.SelectAndPick([]string{"a", "b", "untested"})
		if actual != expected {
			t.Errorf("expected: %v, actual: %v", expected, actual)
		}
	}
*/
func TestSelectLeastExpected(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: nil,
			Expected:  3,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 100},
		{Tag: "b", RTTDeviationCost: 200},
		{Tag: "c", RTTDeviationCost: 300},
		{Tag: "d", RTTDeviationCost: 350},
	}
	expected := 3
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
func TestSelectLeastExpected2(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: nil,
			Expected:  3,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 100},
		{Tag: "b", RTTDeviationCost: 200},
	}
	expected := 2
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
func TestSelectLeastExpectedAndBaselines(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: []int64{200, 300, 400},
			Expected:  3,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 100},
		{Tag: "b", RTTDeviationCost: 200},
		{Tag: "c", RTTDeviationCost: 250},
		{Tag: "d", RTTDeviationCost: 300},
		{Tag: "e", RTTDeviationCost: 310},
	}
	expected := 3
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
func TestSelectLeastExpectedAndBaselines2(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: []int64{200, 300, 400},
			Expected:  3,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 500},
		{Tag: "b", RTTDeviationCost: 600},
		{Tag: "c", RTTDeviationCost: 700},
		{Tag: "d", RTTDeviationCost: 800},
		{Tag: "e", RTTDeviationCost: 900},
	}
	expected := 3
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
func TestSelectLeastLoadBaselines(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: []int64{200, 400, 600},
			Expected:  0,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 100},
		{Tag: "b", RTTDeviationCost: 200},
		{Tag: "c", RTTDeviationCost: 300},
	}
	expected := 1
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
func TestSelectLeastLoadBaselinesNoQualified(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: []int64{200, 400, 600},
			Expected:  0,
		},
	}
	nodes := []*node{
		{Tag: "a", RTTDeviationCost: 800},
		{Tag: "b", RTTDeviationCost: 1000},
	}
	expected := 0
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}

func TestLeastLoadToleranceDisabledKeepsCandidate(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{})
	strategy.ctx = context.Background()
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       50,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:  10,
						Fail: 9,
					},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a"}); got != "node-a" {
		t.Fatalf("expected node-a to remain eligible when tolerance is disabled, got %q", got)
	}
}

func TestLeastLoadToleranceFiltersCandidate(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Tolerance: 0.5})
	strategy.ctx = context.Background()
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       50,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:  10,
						Fail: 9,
					},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a"}); got != "" {
		t.Fatalf("expected node-a to be filtered by tolerance, got %q", got)
	}
}

func TestLeastLoadKeepsCurrentWinnerWhenStillQualified(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 2})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-b"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{Alive: true, Delay: 50, OutboundTag: "node-a"},
				{Alive: true, Delay: 60, OutboundTag: "node-b"},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-b" {
		t.Fatalf("expected sticky selection to keep node-b, got %q", got)
	}
}

func TestLeastLoadColdStartFallsBackToSortedCandidate(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{})
	strategy.ctx = context.Background()
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{},
	}

	if got := strategy.PickOutbound([]string{"node-b", "node-a"}); got != "node-a" {
		t.Fatalf("expected cold start fallback to select node-a, got %q", got)
	}
}

func TestLeastLoadObservedDeadReturnsEmpty(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{})
	strategy.ctx = context.Background()
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{Alive: false, Delay: 99999999, OutboundTag: "node-a"},
				{Alive: false, Delay: 99999999, OutboundTag: "node-b"},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "" {
		t.Fatalf("expected observed dead candidates to force fallback, got %q", got)
	}
}

func TestLeastLoadMinSamplesDisabledPreservesCurrentBehavior(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-b"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       50,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       1,
						Fail:      0,
						Average:   int64(50 * 1_000_000),
						Deviation: int64(10 * 1_000_000),
					},
				},
				{
					Alive:       true,
					Delay:       60,
					OutboundTag: "node-b",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       10,
						Fail:      0,
						Average:   int64(60 * 1_000_000),
						Deviation: int64(20 * 1_000_000),
					},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected under-sampled node-a to remain eligible when minSamples is disabled, got %q", got)
	}
}

func TestLeastLoadMinSamplesKeepsHealthyCurrentWinner(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, MinSamples: 2})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-b"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       50,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       1,
						Fail:      0,
						Average:   int64(50 * 1_000_000),
						Deviation: int64(10 * 1_000_000),
					},
				},
				{
					Alive:       true,
					Delay:       60,
					OutboundTag: "node-b",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       10,
						Fail:      0,
						Average:   int64(60 * 1_000_000),
						Deviation: int64(20 * 1_000_000),
					},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-b" {
		t.Fatalf("expected minSamples to keep the healthy current winner, got %q", got)
	}
}

func TestLeastLoadMinSamplesBypassesDeadCurrentWinner(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, MinSamples: 5})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-b"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       50,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       1,
						Fail:      0,
						Average:   int64(50 * 1_000_000),
						Deviation: int64(10 * 1_000_000),
					},
				},
				{Alive: false, Delay: 99999999, OutboundTag: "node-b"},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected replacement to bypass warmup when current winner is dead, got %q", got)
	}
}

func TestLeastLoadMinSamplesIgnoresLegacyObservations(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, MinSamples: 10})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-b"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{Alive: true, Delay: 50, OutboundTag: "node-a"},
				{Alive: true, Delay: 60, OutboundTag: "node-b"},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected legacy observations to ignore minSamples filtering, got %q", got)
	}
}

func TestLeastLoadSoftFailGraceDisabledKeepsOldBehavior(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, MaxRTT: int64(2 * time.Second)})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-a"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{Alive: true, Delay: 3000, OutboundTag: "node-a", LastTryTime: 100},
				{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 100},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-b" {
		t.Fatalf("expected soft-failing node-a to be replaced when grace is disabled, got %q", got)
	}
}

func TestLeastLoadSoftFailGraceUsesObservationCycles(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, MaxRTT: int64(2 * time.Second), SoftFailGrace: 2})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-a"
	strategy.observer = &sequenceObservatory{
		results: []proto.Message{
			&observatory.ObservationResult{
				Status: []*observatory.OutboundStatus{
					{Alive: true, Delay: 3000, OutboundTag: "node-a", LastTryTime: 10},
					{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 10},
				},
			},
			&observatory.ObservationResult{
				Status: []*observatory.OutboundStatus{
					{Alive: true, Delay: 3000, OutboundTag: "node-a", LastTryTime: 10},
					{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 10},
				},
			},
			&observatory.ObservationResult{
				Status: []*observatory.OutboundStatus{
					{Alive: true, Delay: 3000, OutboundTag: "node-a", LastTryTime: 11},
					{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 11},
				},
			},
			&observatory.ObservationResult{
				Status: []*observatory.OutboundStatus{
					{Alive: true, Delay: 3000, OutboundTag: "node-a", LastTryTime: 12},
					{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 12},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected first soft-fail cycle to keep node-a, got %q", got)
	}
	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected repeated picks in the same cycle to keep node-a, got %q", got)
	}
	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected second soft-fail cycle to keep node-a, got %q", got)
	}
	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-b" {
		t.Fatalf("expected grace to expire after two soft-fail cycles, got %q", got)
	}
}

func TestLeastLoadSoftFailGraceBypassesDeadCurrentWinner(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1, SoftFailGrace: 3})
	strategy.ctx = context.Background()
	strategy.lastSelected = "node-a"
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{Alive: false, Delay: 99999999, OutboundTag: "node-a", LastTryTime: 100},
				{Alive: true, Delay: 50, OutboundTag: "node-b", LastTryTime: 100},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-b" {
		t.Fatalf("expected dead current winner to bypass grace immediately, got %q", got)
	}
}

func TestLeastLoadPrefersLowerFailRatioOverLowerRawFailCount(t *testing.T) {
	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{Expected: 1})
	strategy.ctx = context.Background()
	strategy.observer = &staticObservatory{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					Alive:       true,
					Delay:       100,
					OutboundTag: "node-a",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       100,
						Fail:      10,
						Average:   int64(100 * 1_000_000),
						Deviation: int64(20 * 1_000_000),
					},
				},
				{
					Alive:       true,
					Delay:       100,
					OutboundTag: "node-b",
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       10,
						Fail:      2,
						Average:   int64(100 * 1_000_000),
						Deviation: int64(20 * 1_000_000),
					},
				},
			},
		},
	}

	if got := strategy.PickOutbound([]string{"node-a", "node-b"}); got != "node-a" {
		t.Fatalf("expected lower fail-ratio node-a to win, got %q", got)
	}
}

type staticObservatory struct {
	result proto.Message
	err    error
}

func (s *staticObservatory) Start() error { return nil }

func (s *staticObservatory) Close() error { return nil }

func (s *staticObservatory) Type() interface{} { return nil }

func (s *staticObservatory) GetObservation(ctx context.Context) (proto.Message, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

type sequenceObservatory struct {
	results []proto.Message
	index   int
}

func (s *sequenceObservatory) Start() error { return nil }

func (s *sequenceObservatory) Close() error { return nil }

func (s *sequenceObservatory) Type() interface{} { return nil }

func (s *sequenceObservatory) GetObservation(ctx context.Context) (proto.Message, error) {
	if len(s.results) == 0 {
		return &observatory.ObservationResult{}, nil
	}
	if s.index >= len(s.results) {
		return s.results[len(s.results)-1], nil
	}
	result := s.results[s.index]
	s.index++
	return result, nil
}
