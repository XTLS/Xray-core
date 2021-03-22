package router_test

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	. "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/testing/mocks"
)

type mockOutboundManager struct {
	outbound.Manager
	outbound.HandlerSelector
}

func TestSimpleRouter(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "test",
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
	common.Must(r.Init(config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
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
	common.Must(r.Init(config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestIPOnDemand(t *testing.T) {
	config := &Config{
		DomainStrategy: Config_IpOnDemand,
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "test",
				},
				Cidr: []*CIDR{
					{
						Ip:     []byte{192, 168, 0, 0},
						Prefix: 16,
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
	}).Return([]net.IP{{192, 168, 0, 1}}, nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(config, mockDNS, nil))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
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
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "test",
				},
				Cidr: []*CIDR{
					{
						Ip:     []byte{192, 168, 0, 0},
						Prefix: 16,
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
	}).Return([]net.IP{{192, 168, 0, 1}}, nil).AnyTimes()

	r := new(Router)
	common.Must(r.Init(config, mockDNS, nil))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
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
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "test",
				},
				Cidr: []*CIDR{
					{
						Ip:     []byte{127, 0, 0, 0},
						Prefix: 8,
					},
				},
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)

	r := new(Router)
	common.Must(r.Init(config, mockDNS, nil))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.LocalHostIP, 80)})
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestRouter_AddRoutingRule(t *testing.T) {
	config := &Config{}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	r := new(Router)
	common.Must(r.Init(config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
	err := r.AddRule(ctx, -1, &RoutingRule{
		TargetTag: &RoutingRule_OutboundTag{
			OutboundTag: "test",
		},
		Domain: []*Domain{
			{
				Type:  Domain_Domain,
				Value: "example.com",
			},
		},
	})
	common.Must(err)

	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestRouter_AlterRoutingRule(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "example",
				},
				Networks: []net.Network{net.Network_TCP},
				Tag:      "test",
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	r := new(Router)
	common.Must(r.Init(config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
	err := r.AlterRule(ctx, "test", &RoutingRule{
		TargetTag: &RoutingRule_OutboundTag{
			OutboundTag: "test",
		},
		Domain: []*Domain{
			{
				Type:  Domain_Domain,
				Value: "example.com",
			},
		},
		Tag: "test",
	})
	common.Must(err)
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}

func TestRouter_RemoveRoutingRule(t *testing.T) {
	config := &Config{
		Rule: []*RoutingRule{
			{
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "example",
				},
				Domain: []*Domain{
					{
						Type:  Domain_Domain,
						Value: "example.com",
					},
				},
				Tag: "example",
			},
			{
				TargetTag: &RoutingRule_OutboundTag{
					OutboundTag: "test",
				},
				Networks: []net.Network{net.Network_TCP},
				Tag:      "test",
			},
		},
	}

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	mockDNS := mocks.NewDNSClient(mockCtl)
	mockOhm := mocks.NewOutboundManager(mockCtl)
	mockHs := mocks.NewOutboundHandlerSelector(mockCtl)

	r := new(Router)
	common.Must(r.Init(config, mockDNS, &mockOutboundManager{
		Manager:         mockOhm,
		HandlerSelector: mockHs,
	}))

	ctx := session.ContextWithOutbound(context.Background(), &session.Outbound{Target: net.TCPDestination(net.DomainAddress("example.com"), 80)})
	err := r.RemoveRule(ctx, "example")
	common.Must(err)
	route, err := r.PickRoute(routing_session.AsRoutingContext(ctx))
	common.Must(err)
	if tag := route.GetOutboundTag(); tag != "test" {
		t.Error("expect tag 'test', bug actually ", tag)
	}
}
