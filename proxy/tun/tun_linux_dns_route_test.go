//go:build linux && !android

package tun

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy/blackhole"
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/freedom"
)

const (
	routeTestInboundTag = "tun"
	routeTestSource     = "192.168.100.1"
	routeTestDNSAddress = "192.168.100.2"
)

// port53Rule sends DNS queries arriving from the interface to the dns outbound.
func port53Rule() *router.RoutingRule {
	return &router.RoutingRule{
		InboundTag: []string{routeTestInboundTag},
		PortList:   &net.PortList{Range: []*net.PortRange{net.SinglePortRange(53)}},
		TargetTag:  &router.RoutingRule_Tag{Tag: "dns"},
	}
}

// sourceBlockRule diverts traffic from one address, which is the shape of a rule
// that only matches because the real request carries a source.
func sourceBlockRule(ip []byte) *router.RoutingRule {
	return &router.RoutingRule{
		SourceIp: []*geodata.IPRule{{
			Value: &geodata.IPRule_Custom{
				Custom: &geodata.CIDRRule{
					Cidr: &geodata.CIDR{Ip: ip, Prefix: 32},
				},
			},
		}},
		TargetTag: &router.RoutingRule_Tag{Tag: "block"},
	}
}

// newRouteTestContext builds a real but unstarted instance: no TUN device, no
// running resolver. The instance is placed in the context through the key core
// exports for tests.
func newRouteTestContext(t *testing.T, withDNSApp bool, nameServers []*appdns.NameServer, rules []*router.RoutingRule) context.Context {
	t.Helper()

	apps := []*serial.TypedMessage{
		serial.ToTypedMessage(&dispatcher.Config{}),
		serial.ToTypedMessage(&proxyman.InboundConfig{}),
		serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		serial.ToTypedMessage(&router.Config{Rule: rules}),
	}
	if withDNSApp {
		apps = append(apps, serial.ToTypedMessage(&appdns.Config{NameServer: nameServers}))
	}

	instance, err := core.New(&core.Config{
		App: apps,
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{})},
			{Tag: "dns", ProxySettings: serial.ToTypedMessage(&proxydns.Config{})},
			{Tag: "block", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})},
		},
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	return context.WithValue(context.Background(), core.XrayKey(1), instance)
}

func udpNameServer(ip []byte) []*appdns.NameServer {
	return []*appdns.NameServer{{
		Address: &net.Endpoint{
			Network: net.Network_UDP,
			Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: ip}},
			Port:    53,
		},
	}}
}

// These drive the real feature lookup and the real router. verifyDNSRouting is
// the same function ConfigureSystemDNS calls, so a false positive here is a
// false positive in the takeover decision itself, which is what assertions on
// the resolvectl arguments could never catch.
func TestVerifyDNSRoutingDecisions(t *testing.T) {
	tests := []struct {
		name        string
		withDNSApp  bool
		nameServers []*appdns.NameServer
		rules       []*router.RoutingRule
		wantErr     string
	}{
		{
			name:        "independent upstream reaches the dns outbound",
			withDNSApp:  true,
			nameServers: udpNameServer([]byte{9, 9, 9, 9}),
			rules:       []*router.RoutingRule{port53Rule()},
			wantErr:     "",
		},
		{
			name:    "no dns section falls back to the system resolver",
			rules:   []*router.RoutingRule{port53Rule()},
			wantErr: "system resolver",
		},
		{
			name:       "dns section without name servers falls back too",
			withDNSApp: true,
			rules:      []*router.RoutingRule{port53Rule()},
			wantErr:    "system resolver",
		},
		{
			name:       "a rule on the interface address diverts the real query",
			withDNSApp: true, nameServers: udpNameServer([]byte{9, 9, 9, 9}),
			rules: []*router.RoutingRule{
				sourceBlockRule([]byte{192, 168, 100, 1}),
				port53Rule(),
			},
			wantErr: "does not handle DNS",
		},
		{
			name:       "a rule on another address does not match it",
			withDNSApp: true, nameServers: udpNameServer([]byte{9, 9, 9, 9}),
			rules: []*router.RoutingRule{
				sourceBlockRule([]byte{10, 0, 0, 1}),
				port53Rule(),
			},
			wantErr: "",
		},
		{
			name:       "no rule matches the query",
			withDNSApp: true, nameServers: udpNameServer([]byte{9, 9, 9, 9}),
			wantErr: "no route",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newRouteTestContext(t, tt.withDNSApp, tt.nameServers, tt.rules)
			err := verifyDNSRouting(ctx, routeTestInboundTag, routeTestSource, routeTestDNSAddress)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected the takeover to be accepted, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected the takeover to be refused with %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
