package router_test

import (
	"context"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/xtls/xray-core/app/observatory"
	. "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/testing/mocks"
	"google.golang.org/protobuf/proto"
)

type mockOutboundManager struct {
	outbound.Manager
	outbound.HandlerSelector
}

type sequencedHandlerSelector struct {
	sequences map[string][][]string
	calls     map[string]int
}

func (s *sequencedHandlerSelector) Select(selectors []string) []string {
	key := strings.Join(selectors, "\x00")
	index := s.calls[key]
	s.calls[key] = index + 1
	entries := s.sequences[key]
	if index >= len(entries) {
		return nil
	}
	return entries[index]
}

type fakeObservatory struct {
	result *observatory.ObservationResult
}

func (f *fakeObservatory) Type() interface{} {
	return extension.ObservatoryType()
}

func (f *fakeObservatory) Start() error { return nil }

func (f *fakeObservatory) Close() error { return nil }

func (f *fakeObservatory) GetObservation(context.Context) (proto.Message, error) {
	return f.result, nil
}

func testContextWithObservatory(t *testing.T, statuses ...*observatory.OutboundStatus) context.Context {
	t.Helper()

	instance := new(core.Instance)
	if err := instance.AddFeature(&fakeObservatory{
		result: &observatory.ObservationResult{Status: statuses},
	}); err != nil {
		t.Fatalf("AddFeature() failed: %v", err)
	}

	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func TestSimpleRouter(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestSimpleBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "balance",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				OutboundSelector: []string{"test-"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{"test"})

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestBalancerFallsBackToFallbackOutboundTag(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance"},
				Networks:  []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:                 "balance",
				OutboundSelector:    []string{"test-"},
				FallbackOutboundTag: "fall",
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{})

	r := new(Router)
	common.Must(r.Init(testContextWithObservatory(t), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "fall" {
		t.Fatalf("expect tag 'fall', got %q", tag)
	}
}

func TestBalancerFallsBackToFallbackBalancerTag(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance-a"},
				Networks:  []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:                 "balance-a",
				OutboundSelector:    []string{"test-a-"},
				FallbackBalancerTag: "balance-b",
			},
			{
				Tag:              "balance-b",
				OutboundSelector: []string{"test-b-"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)
	gomock.InOrder(
		mockHs.EXPECT().Select(gomock.Eq([]string{"test-a-"})).Return([]string{}),
		mockHs.EXPECT().Select(gomock.Eq([]string{"test-b-"})).Return([]string{"fallback"}),
	)

	r := new(Router)
	common.Must(r.Init(testContextWithObservatory(t), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "fallback" {
		t.Fatalf("expect tag 'fallback', got %q", tag)
	}
}

func TestBalancerRetriesPrimaryBeforeFallbackBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{BalancingTag: "balance-a"},
				Networks:  []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:                 "balance-a",
				OutboundSelector:    []string{"test-a-"},
				FallbackBalancerTag: "balance-b",
			},
			{
				Tag:              "balance-b",
				OutboundSelector: []string{"test-b-"},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	selector := &sequencedHandlerSelector{
		sequences: map[string][][]string{
			"test-a-": {[]string{}, []string{"primary"}},
			"test-b-": {[]string{"fallback"}},
		},
		calls: make(map[string]int),
	}

	r := new(Router)
	common.Must(r.Init(testContextWithObservatory(t), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: selector,
	}, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})

	first, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := first.GetOutboundTag(); tag != "fallback" {
		t.Fatalf("expect first tag 'fallback', got %q", tag)
	}

	second, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := second.GetOutboundTag(); tag != "primary" {
		t.Fatalf("expect second tag 'primary', got %q", tag)
	}
}

func TestRouterInitRejectsUnknownFallbackBalancerTag(t *testing.T) {
	config := &Config{
		BalancingRule: []*BalancingRule{
			{
				Tag:                 "balance-a",
				OutboundSelector:    []string{"test-a-"},
				FallbackBalancerTag: "missing",
			},
		},
	}

	r := new(Router)
	if err := r.Init(testContextWithObservatory(t), config, nil, nil, nil); err == nil {
		t.Fatal("expected unknown fallback balancer tag to fail")
	} else if !strings.Contains(err.Error(), "missing") || !strings.Contains(err.Error(), "fallback") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRouterInitRejectsFallbackBalancerCycle(t *testing.T) {
	config := &Config{
		BalancingRule: []*BalancingRule{
			{
				Tag:                 "balance-a",
				OutboundSelector:    []string{"test-a-"},
				FallbackBalancerTag: "balance-b",
			},
			{
				Tag:                 "balance-b",
				OutboundSelector:    []string{"test-b-"},
				FallbackBalancerTag: "balance-a",
			},
		},
	}

	r := new(Router)
	if err := r.Init(testContextWithObservatory(t), config, nil, nil, nil); err == nil {
		t.Fatal("expected fallback balancer cycle to fail")
	} else if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("unexpected error: %v", err)
	}
}

/*

Do not work right now: need a full client setup

func TestLeastLoadBalancer(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_BalancingTag{
					BalancingTag: "balance",
				},
				Networks: []net.Network{net.Network_TCP},
			},
		},
		BalancingRule: []*BalancingRule{
			{
				Tag:              "balance",
				OutboundSelector: []string{"test-"},
				Strategy:         "leastLoad",
				StrategySettings: serial.ToTypedMessage(&StrategyLeastLoadConfig{
					Baselines:   nil,
					Expected:    1,
				}),
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	mockHs.EXPECT().Select(gomock.Eq([]string{"test-"})).Return([]string{"test1"})

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}, nil))
	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("v2ray.com"), 80)})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test1" {
		t.Error("expect tag 'test1', bug actually ", tag)
	}
}*/

func TestIPOnDemand(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpOnDemand,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Ip: []*geodata.IPRule{
					{
						Value: &geodata.IPRule_Custom{
							Custom: &geodata.CIDR{
								Ip:     []byte{192, 168, 0, 0},
								Prefix: 16,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockDNS.EXPECT().LookupIP(gomock.Eq("example.com"), dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}).Return([]net.IP{{192, 168, 0, 1}}, uint32(600), nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestIPIfNonMatchDomain(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Ip: []*geodata.IPRule{
					{
						Value: &geodata.IPRule_Custom{
							Custom: &geodata.CIDR{
								Ip:     []byte{192, 168, 0, 0},
								Prefix: 16,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockDNS.EXPECT().LookupIP(gomock.Eq("example.com"), dns.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
		FakeEnable: false,
	}).Return([]net.IP{{192, 168, 0, 1}}, uint32(600), nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestIPIfNonMatchIP(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpIfNonMatch,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_Tag{
					Tag: "test",
				},
				Ip: []*geodata.IPRule{
					{
						Value: &geodata.IPRule_Custom{
							Custom: &geodata.CIDR{
								Ip:     []byte{127, 0, 0, 0},
								Prefix: 8,
							},
						},
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)

	r := new(Router)
	common.Must(r.Init(context.TODO(), config, mockDNS, nil, nil))

	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.LocalHostIP, 80),
	}})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}
