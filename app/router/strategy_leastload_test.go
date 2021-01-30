package router

import (
	"testing"
	"time"
)

func TestSelectLeastLoad(t *testing.T) {
	settings := &StrategyLeastLoadConfig{
		HealthCheck: &HealthPingConfig{
			SamplingCount: 10,
		},
		Expected: 1,
		MaxRTT:   int64(time.Millisecond * time.Duration(800)),
	}
	strategy := NewLeastLoadStrategy(settings, nil)
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

func TestSelectLeastExpected(t *testing.T) {
	strategy := &LeastLoadStrategy{
		settings: &StrategyLeastLoadConfig{
			Baselines: nil,
			Expected:  3,
		},
	}
	nodes := []*node{
		{Tag: "a", applied: 100},
		{Tag: "b", applied: 200},
		{Tag: "c", applied: 300},
		{Tag: "d", applied: 350},
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
		{Tag: "a", applied: 100},
		{Tag: "b", applied: 200},
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
		{Tag: "a", applied: 100},
		{Tag: "b", applied: 200},
		{Tag: "c", applied: 250},
		{Tag: "d", applied: 300},
		{Tag: "e", applied: 310},
	}
	expected := 4
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
		{Tag: "a", applied: 500},
		{Tag: "b", applied: 600},
		{Tag: "c", applied: 700},
		{Tag: "d", applied: 800},
		{Tag: "e", applied: 900},
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
		{Tag: "a", applied: 100},
		{Tag: "b", applied: 200},
		{Tag: "c", applied: 300},
	}
	expected := 2
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
		{Tag: "a", applied: 800},
		{Tag: "b", applied: 1000},
	}
	expected := 0
	ns := strategy.selectLeastLoad(nodes)
	if len(ns) != expected {
		t.Errorf("expected: %v, actual: %v", expected, len(ns))
	}
}
