package router

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/features/outbound"
)

type pickerCandidates struct {
	outbound.Manager
	tags []string
}

func (m *pickerCandidates) Select([]string) []string { return m.tags }

func TestBalancerPickerUsesExistingStrategyAndFallback(t *testing.T) {
	m := &pickerCandidates{tags: []string{"a", "b", "c"}}
	b := &Balancer{ohm: m, strategy: &RoundRobinStrategy{}, fallbackTag: "direct"}
	r := new(Router)
	r.balancers.Store(&map[string]*Balancer{"entries": b})
	for _, want := range []string{"a", "b", "c", "a"} {
		got, err := r.PickOutbound("entries")
		if err != nil || got != want {
			t.Fatalf("got %q, %v; want %q", got, err, want)
		}
	}
	common.Must(r.SetOverrideTarget("entries", "c"))
	if got, err := r.PickOutbound("entries"); err != nil || got != "c" {
		t.Fatalf("override: %q, %v", got, err)
	}
	common.Must(r.SetOverrideTarget("entries", ""))
	m.tags = nil
	if got, err := r.PickOutbound("entries"); err != nil || got != "direct" {
		t.Fatalf("fallback: %q, %v", got, err)
	}
	if _, err := r.PickOutbound("missing"); err == nil {
		t.Fatal("missing balancer accepted")
	}
}

func TestBalancerPickerUsesReloadedRules(t *testing.T) {
	m := &pickerCandidates{tags: []string{"a"}}
	r := new(Router)
	config := &Config{BalancingRule: []*BalancingRule{{Tag: "before", Strategy: "roundRobin"}}}
	common.Must(r.Init(context.Background(), config, nil, m, nil))
	common.Must(r.ReloadRules(&Config{BalancingRule: []*BalancingRule{{Tag: "after", Strategy: "roundRobin"}}}, false))
	if _, err := r.PickOutbound("before"); err == nil {
		t.Fatal("stale balancer used after reload")
	}
	if got, err := r.PickOutbound("after"); err != nil || got != "a" {
		t.Fatalf("new balancer: %q, %v", got, err)
	}
}
