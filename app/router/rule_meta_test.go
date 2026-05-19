package router

import (
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func TestRouteIndexInboundOrder(t *testing.T) {
	r := &Router{}
	rules := []*Rule{
		mustRule(t, &RoutingRule{Domain: []*geodata.DomainRule{domainRule("global.com")}}, "global"),
		mustRule(t, &RoutingRule{
			InboundTag: []string{"in-a"},
			Domain:     []*geodata.DomainRule{domainRule("a.com")},
		}, "a"),
		mustRule(t, &RoutingRule{Domain: []*geodata.DomainRule{domainRule("later.com")}}, "later"),
	}
	r.rules = rules
	for _, rule := range rules {
		rule.meta = buildRuleMeta(rule.Condition)
	}
	r.rebuildRouteIndex()

	ctx := &routing_session.Context{
		Inbound: &session.Inbound{Tag: "in-a"},
		Outbound: &session.Outbound{
			Target: net.TCPDestination(net.DomainAddress("a.com"), 443),
		},
	}
	rule, _, ok := r.matchRules(ctx)
	if !ok || rule.Tag != "a" {
		t.Fatalf("expected inbound rule a, got %v ok=%v", rule, ok)
	}
}

func domainRule(value string) *geodata.DomainRule {
	return &geodata.DomainRule{
		Value: &geodata.DomainRule_Custom{
			Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: value},
		},
	}
}

func BenchmarkRouteIndexPick(b *testing.B) {
	r := &Router{}
	rules := make([]*Rule, 0, 128)
	for i := 0; i < 100; i++ {
		rules = append(rules, mustRule(b, &RoutingRule{
			InboundTag: []string{"in-a"},
			Domain:     []*geodata.DomainRule{domainRule("example.com")},
		}, "tag"))
	}
	rules = append(rules, mustRule(b, &RoutingRule{
		InboundTag: []string{"in-a"},
		Domain:     []*geodata.DomainRule{domainRule("target.com")},
	}, "hit"))
	for _, rule := range rules {
		rule.meta = buildRuleMeta(rule.Condition)
	}
	r.rules = rules
	r.rebuildRouteIndex()

	ctx := &routing_session.Context{
		Inbound: &session.Inbound{Tag: "in-a"},
		Outbound: &session.Outbound{
			Target: net.TCPDestination(net.DomainAddress("target.com"), 443),
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = r.matchRules(ctx)
	}
}

func mustRule(t testing.TB, rr *RoutingRule, tag string) *Rule {
	t.Helper()
	cond, err := rr.BuildCondition()
	if err != nil {
		t.Fatal(err)
	}
	return &Rule{Condition: cond, Tag: tag, RuleTag: tag}
}
