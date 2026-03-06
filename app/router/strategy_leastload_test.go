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

type mockLeastLoadObserver struct {
	result *observatory.ObservationResult
	err    error
}

func (m *mockLeastLoadObserver) Type() interface{} {
	return nil
}

func (m *mockLeastLoadObserver) Start() error {
	return nil
}

func (m *mockLeastLoadObserver) Close() error {
	return nil
}

func (m *mockLeastLoadObserver) GetObservation(ctx context.Context) (proto.Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func TestLeastLoadToleranceFiltersFailureRate(t *testing.T) {
	t.Parallel()

	strategy := NewLeastLoadStrategy(&StrategyLeastLoadConfig{
		Tolerance: 0.5,
	})
	strategy.ctx = context.Background()
	strategy.observer = &mockLeastLoadObserver{
		result: &observatory.ObservationResult{
			Status: []*observatory.OutboundStatus{
				{
					OutboundTag: "drop",
					Alive:       true,
					Delay:       50,
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       10,
						Fail:      6,
						Average:   int64(50 * time.Millisecond),
						Deviation: int64(5 * time.Millisecond),
					},
				},
				{
					OutboundTag: "keep_edge",
					Alive:       true,
					Delay:       40,
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:       10,
						Fail:      5,
						Average:   int64(40 * time.Millisecond),
						Deviation: int64(4 * time.Millisecond),
					},
				},
				{
					OutboundTag: "keep_unknown",
					Alive:       true,
					Delay:       60,
				},
				{
					OutboundTag: "keep_all_zero",
					Alive:       true,
					Delay:       70,
					HealthPing: &observatory.HealthPingMeasurementResult{
						All:  0,
						Fail: 0,
					},
				},
			},
		},
	}

	nodes := strategy.getNodes([]string{"drop", "keep_edge", "keep_unknown", "keep_all_zero"}, 0)
	got := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		got[node.Tag] = struct{}{}
	}

	if _, found := got["drop"]; found {
		t.Fatal("expected 'drop' to be filtered out by tolerance")
	}
	for _, tag := range []string{"keep_edge", "keep_unknown", "keep_all_zero"} {
		if _, found := got[tag]; !found {
			t.Fatalf("expected %q to remain eligible", tag)
		}
	}
}
