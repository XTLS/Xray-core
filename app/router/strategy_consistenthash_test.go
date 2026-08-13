package router

import (
	"context"
	"fmt"
	"testing"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"google.golang.org/protobuf/proto"
)

type consistentHashObservatory struct {
	result proto.Message
	err    error
}

func (o *consistentHashObservatory) Type() interface{} {
	return extension.ObservatoryType()
}

func (o *consistentHashObservatory) Start() error {
	return nil
}

func (o *consistentHashObservatory) Close() error {
	return nil
}

func (o *consistentHashObservatory) GetObservation(context.Context) (proto.Message, error) {
	return o.result, o.err
}

type consistentHashOutboundManager struct {
	outbound.Manager
	candidates []string
}

func (m *consistentHashOutboundManager) Select([]string) []string {
	return m.candidates
}

func consistentHashRoutingContext(target, routeTarget net.Destination) routing.Context {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target:      target,
		RouteTarget: routeTarget,
	}})
	return routing_session.AsRoutingContext(ctx)
}

func TestConsistentHashTargetCanonicalization(t *testing.T) {
	domainUpper := consistentHashRoutingContext(
		net.TCPDestination(net.DomainAddress("Example.COM."), 443),
		net.Destination{},
	)
	domainLower := consistentHashRoutingContext(
		net.UDPDestination(net.DomainAddress("example.com"), 53),
		net.Destination{},
	)
	if upper, lower := consistentHashTarget(domainUpper), consistentHashTarget(domainLower); upper != lower {
		t.Fatalf("同一域名的规范化哈希键不一致：%q != %q", upper, lower)
	}

	ipTarget := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 443)
	domainWithResolvedIP := consistentHashRoutingContext(
		ipTarget,
		net.TCPDestination(net.DomainAddress("example.com"), 443),
	)
	if got, want := consistentHashTarget(domainWithResolvedIP), consistentHashTarget(domainLower); got != want {
		t.Fatalf("同时存在域名和 IP 时应优先使用域名：%q != %q", got, want)
	}

	ipTCP := consistentHashRoutingContext(ipTarget, net.Destination{})
	ipUDP := consistentHashRoutingContext(
		net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 5353),
		net.Destination{},
	)
	if tcp, udp := consistentHashTarget(ipTCP), consistentHashTarget(ipUDP); tcp != udp {
		t.Fatalf("同一 IP 不应受端口或网络类型影响：%q != %q", tcp, udp)
	}
}

func TestConsistentHashSelectionIsStable(t *testing.T) {
	candidates := []string{"outbound-a", "outbound-b", "outbound-c"}
	reordered := []string{"outbound-c", "outbound-a", "outbound-b"}
	strategy := new(ConsistentHashStrategy)
	target := consistentHashRoutingContext(
		net.TCPDestination(net.DomainAddress("example.com"), 443),
		net.Destination{},
	)

	want := strategy.PickOutboundForContext(candidates, target)
	for i := 0; i < 100; i++ {
		if got := strategy.PickOutboundForContext(candidates, target); got != want {
			t.Fatalf("同一目标的选择不稳定：第 %d 次得到 %q，期望 %q", i, got, want)
		}
	}
	if got := strategy.PickOutboundForContext(reordered, target); got != want {
		t.Fatalf("候选项顺序不应改变选择：得到 %q，期望 %q", got, want)
	}
}

func TestConsistentHashStableVectors(t *testing.T) {
	candidates := []string{"outbound-a", "outbound-b", "outbound-c"}
	tests := []struct {
		target string
		want   string
	}{
		{target: "domain\x00site-2.example", want: "outbound-a"},
		{target: "domain\x00site-5.example", want: "outbound-b"},
		{target: "domain\x00example.com", want: "outbound-c"},
	}

	for _, test := range tests {
		if got := pickConsistentHashOutbound(test.target, candidates); got != test.want {
			t.Errorf("目标 %q 得到 %q，期望稳定映射到 %q", test.target, got, test.want)
		}
	}
}

func TestConsistentHashMinimizesRemapping(t *testing.T) {
	allCandidates := []string{"outbound-a", "outbound-b", "outbound-c"}
	remainingCandidates := []string{"outbound-a", "outbound-c"}
	selectedCounts := make(map[string]int)

	for i := 0; i < 1000; i++ {
		target := fmt.Sprintf("domain\x00site-%d.example", i)
		before := pickConsistentHashOutbound(target, allCandidates)
		after := pickConsistentHashOutbound(target, remainingCandidates)
		selectedCounts[before]++
		if before != "outbound-b" && after != before {
			t.Fatalf("移除未命中的候选项后发生了不必要的迁移：目标 %q 从 %q 迁移到 %q", target, before, after)
		}
	}

	for _, candidate := range allCandidates {
		if selectedCounts[candidate] == 0 {
			t.Fatalf("候选项 %q 未分配到任何目标，哈希分布异常", candidate)
		}
	}
}

func TestConsistentHashFallsBackWhenSelectedOutboundIsDown(t *testing.T) {
	candidates := []string{"outbound-a", "outbound-b", "outbound-c"}
	target := consistentHashRoutingContext(
		net.TCPDestination(net.DomainAddress("example.com"), 443),
		net.Destination{},
	)
	selected := new(ConsistentHashStrategy).PickOutboundForContext(candidates, target)

	statuses := make([]*observatory.OutboundStatus, 0, len(candidates))
	for _, candidate := range candidates {
		statuses = append(statuses, &observatory.OutboundStatus{
			OutboundTag: candidate,
			Alive:       candidate != selected,
		})
	}
	strategy := &ConsistentHashStrategy{
		ctx: context.Background(),
		observatory: &consistentHashObservatory{
			result: &observatory.ObservationResult{Status: statuses},
		},
	}
	balancer := &Balancer{
		selectors:   []string{"outbound-"},
		strategy:    strategy,
		ohm:         &consistentHashOutboundManager{candidates: candidates},
		fallbackTag: "fallback",
	}

	got, err := balancer.PickOutboundForContext(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != "fallback" {
		t.Fatalf("命中的主出站 %q 失活后得到 %q，期望 fallback", selected, got)
	}

	for _, status := range statuses {
		if status.OutboundTag == selected {
			status.Alive = true
		}
	}
	got, err = balancer.PickOutboundForContext(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != selected {
		t.Fatalf("命中的主出站恢复后得到 %q，期望 %q", got, selected)
	}
}

func TestRouterPassesTargetToConsistentHashStrategy(t *testing.T) {
	candidates := []string{"outbound-a", "outbound-b", "outbound-c"}
	strategy := new(ConsistentHashStrategy)
	contextless := strategy.PickOutbound(candidates)

	var target routing.Context
	var expected string
	for i := 0; i < 1000; i++ {
		candidateTarget := consistentHashRoutingContext(
			net.TCPDestination(net.DomainAddress(fmt.Sprintf("site-%d.example", i)), 443),
			net.Destination{},
		)
		candidateExpected := strategy.PickOutboundForContext(candidates, candidateTarget)
		if candidateExpected != contextless {
			target = candidateTarget
			expected = candidateExpected
			break
		}
	}
	if target == nil {
		t.Fatal("未找到可区分上下文选择与无上下文选择的测试目标")
	}

	router := new(Router)
	err := router.Init(context.Background(), &Config{
		Rule: []*RoutingRule{{
			TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance"},
			Networks:  []net.Network{net.Network_TCP},
		}},
		BalancingRule: []*BalancingRule{{
			Tag:              "balance",
			OutboundSelector: []string{"outbound-"},
			Strategy:         "consistenthash",
		}},
	}, nil, &consistentHashOutboundManager{candidates: candidates}, nil)
	if err != nil {
		t.Fatal(err)
	}

	route, err := router.PickRoute(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := route.GetOutboundTag(); got != expected {
		t.Fatalf("路由器未按目标上下文选择出站：得到 %q，期望 %q", got, expected)
	}
}
