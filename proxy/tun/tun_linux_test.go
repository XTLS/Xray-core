//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
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
	proxydns "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/freedom"
)

// testLink returns a minimal netlink.Link whose Attrs().Name is name, so the
// DNS helpers can be exercised without a real TUN device.
func testLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

type probeCall struct {
	inboundTag string
	source     string
	address    string
}

// stubDNSRouting replaces the routing probe for the duration of a test and
// records how it was called, so tests can assert the probe is representative.
func stubDNSRouting(t *testing.T, err error) *[]probeCall {
	t.Helper()
	original := verifyDNSRouting
	calls := []probeCall{}
	verifyDNSRouting = func(_ context.Context, inboundTag, source, address string) error {
		calls = append(calls, probeCall{inboundTag, source, address})
		return err
	}
	t.Cleanup(func() { verifyDNSRouting = original })
	return &calls
}

// recorder installs a resolvectl stub for the duration of a test and returns the
// captured invocations. An empty failOn succeeds every call; otherwise the named
// subcommand fails.
func recorder(t *testing.T, failOn string) *[][]string {
	t.Helper()
	original := resolvectlRunner
	calls := [][]string{}
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if failOn != "" && len(args) > 0 && args[0] == failOn {
			return nil, errors.New("boom")
		}
		return nil, nil
	}
	t.Cleanup(func() { resolvectlRunner = original })
	return &calls
}

func optedInTun() *LinuxTun {
	return &LinuxTun{
		options: &Config{
			Name:                   "xray_tun",
			Gateway:                []string{"192.168.100.1/30"},
			AutoSystemDnsToGateway: true,
		},
		tunLink: testLink("xray_tun"),
	}
}

func joined(calls [][]string) string {
	parts := make([]string, 0, len(calls))
	for _, call := range calls {
		parts = append(parts, strings.Join(call, " "))
	}
	return strings.Join(parts, " | ")
}

func TestConfigureSystemDNSDisabledByDefault(t *testing.T) {
	probes := stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()
	t1.options.AutoSystemDnsToGateway = false

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*probes) != 0 {
		t.Errorf("routing probe must not run when disabled, got %d calls", len(*probes))
	}
	if len(*calls) != 0 {
		t.Errorf("resolvectl must not run when disabled, got %v", *calls)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false when disabled")
	}
}

func TestConfigureSystemDNSNoGateway(t *testing.T) {
	probes := stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()
	t1.options.Gateway = nil

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when no gateway is configured")
	}
	if len(*probes) != 0 {
		t.Errorf("routing probe must not run without a gateway, got %d calls", len(*probes))
	}
	if len(*calls) != 0 {
		t.Errorf("resolvectl must not run without a gateway, got %v", *calls)
	}
}

// This is the case the reviewer flagged: without a routed DNS path, pointing the
// system resolver at the derived address would break resolution outright.
func TestConfigureSystemDNSLeavesOSDNSWhenNoRoute(t *testing.T) {
	probes := stubDNSRouting(t, errors.New("no route"))
	calls := recorder(t, "")

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when the DNS path is unverified")
	}
	if len(*probes) != 1 {
		t.Errorf("routing probe should run once, got %d", len(*probes))
	}
	if len(*calls) != 0 {
		t.Errorf("system DNS must be left untouched, got %v", *calls)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false when the path is unverified")
	}
}

// A real query from the interface carries a source address, and rules may match
// on it, so the probe must not be source-less.
func TestConfigureSystemDNSProbeCarriesSource(t *testing.T) {
	probes := stubDNSRouting(t, nil)
	recorder(t, "")

	t1 := optedInTun()
	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*probes) != 1 {
		t.Fatalf("expected one probe call, got %d", len(*probes))
	}
	got := (*probes)[0]
	if got.source != "192.168.100.1" {
		t.Errorf("probe source = %q, want the interface address %q", got.source, "192.168.100.1")
	}
	if got.address != "192.168.100.2" {
		t.Errorf("probe address = %q, want %q", got.address, "192.168.100.2")
	}
	if got.inboundTag != "tun" {
		t.Errorf("probe inbound tag = %q, want %q", got.inboundTag, "tun")
	}
}

func TestConfigureSystemDNSAppliesResolvectl(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !t1.systemDNSSet {
		t.Fatal("systemDNSSet should be true after a successful takeover")
	}

	want := "resolvectl dns xray_tun 192.168.100.2 | " +
		"resolvectl domain xray_tun ~. | " +
		"resolvectl default-route xray_tun true"
	if got := joined(*calls); got != want {
		t.Errorf("resolvectl calls = %q, want %q", got, want)
	}
}

func TestConfigureSystemDNSIdempotent(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := len(*calls)

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*calls) != before {
		t.Errorf("second call must be a no-op, calls went %d -> %d", before, len(*calls))
	}
}

// A half-applied resolver is worse than none, so a failure mid-sequence reverts.
func TestConfigureSystemDNSRollsBackOnPartialFailure(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "domain")

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when a resolvectl step fails")
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false after a failed takeover")
	}
	if t1.systemDNSDirty {
		t.Error("a successful revert should not leave the resolver dirty")
	}
	if !strings.Contains(joined(*calls), "resolvectl revert xray_tun") {
		t.Errorf("expected a revert after partial failure, got %q", joined(*calls))
	}
}

// If the revert itself fails the settings may still be installed, so the state
// has to be remembered rather than silently dropped.
func TestConfigureSystemDNSRollbackFailureKeepsDirty(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "revert")

	t1 := optedInTun()
	t1.options.Gateway = []string{"192.168.100.1/30"}
	// Make only the rollback path fail: "dns" succeeds, "domain" fails, "revert" fails.
	*calls = nil

	original := resolvectlRunner
	defer func() { resolvectlRunner = original }()
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, append([]string{name}, args...))
		if len(args) > 0 && (args[0] == "domain" || args[0] == "revert") {
			return nil, errors.New("boom")
		}
		return nil, nil
	}

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when domain fails")
	}
	if !t1.systemDNSDirty {
		t.Error("a failed revert must leave the resolver marked dirty")
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet must stay false when the takeover did not complete")
	}
}

// A dirty resolver is retried before anything new is applied.
func TestConfigureSystemDNSRetriesDirtyBeforeApplying(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()
	t1.systemDNSDirty = true

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := joined(*calls)
	if !strings.HasPrefix(got, "resolvectl revert xray_tun") {
		t.Errorf("expected the stale revert first, got %q", got)
	}
	if t1.systemDNSDirty {
		t.Error("a successful retry should clear the dirty flag")
	}
	if !t1.systemDNSSet {
		t.Error("the takeover should proceed once the retry succeeds")
	}
}

func TestUnsetSystemDNSReverts(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "")

	t1 := optedInTun()
	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	*calls = nil

	t1.unsetSystemDNS()
	if t1.systemDNSSet {
		t.Error("systemDNSSet should be false after unset")
	}
	if got := joined(*calls); got != "resolvectl revert xray_tun" {
		t.Errorf("unset calls = %q, want %q", got, "resolvectl revert xray_tun")
	}

	t1.unsetSystemDNS()
	if len(*calls) != 1 {
		t.Errorf("unsetSystemDNS must be idempotent, got %q", joined(*calls))
	}
}

func TestUnsetSystemDNSKeepsDirtyWhenRevertFails(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recorder(t, "revert")

	t1 := optedInTun()
	t1.systemDNSSet = true

	t1.unsetSystemDNS()
	if !t1.systemDNSDirty {
		t.Error("a failed revert during unset must be remembered")
	}
	if got := joined(*calls); !strings.Contains(got, "resolvectl revert xray_tun") {
		t.Errorf("expected a revert attempt, got %q", got)
	}
}

func TestSystemDNSAddrs(t *testing.T) {
	tests := []struct {
		name       string
		gateway    []string
		wantSource string
		wantDNS    string
		wantOK     bool
	}{
		{
			name:       "ipv4 /30",
			gateway:    []string{"192.168.100.1/30"},
			wantSource: "192.168.100.1",
			wantDNS:    "192.168.100.2",
			wantOK:     true,
		},
		{
			name:       "ipv4 /16",
			gateway:    []string{"10.0.0.1/16"},
			wantSource: "10.0.0.1",
			wantDNS:    "10.0.0.2",
			wantOK:     true,
		},
		{
			name:       "first ipv4 wins",
			gateway:    []string{"fc00::1/64", "172.18.0.1/30"},
			wantSource: "172.18.0.1",
			wantDNS:    "172.18.0.2",
			wantOK:     true,
		},
		{
			name:    "no gateway",
			gateway: nil,
			wantOK:  false,
		},
		{
			name:       "ipv6 only",
			gateway:    []string{"fc00::1/64"},
			wantSource: "fc00::1",
			wantDNS:    "fc00::2",
			wantOK:     true,
		},
		{
			name:       "first ipv6 without ipv4",
			gateway:    []string{"fc00::1/64", "fd00::1/64"},
			wantSource: "fc00::1",
			wantDNS:    "fc00::2",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, dnsAddr, ok := systemDNSAddrs(tt.gateway)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if source.String() != tt.wantSource {
				t.Errorf("source = %q, want %q", source.String(), tt.wantSource)
			}
			if dnsAddr.String() != tt.wantDNS {
				t.Errorf("dns = %q, want %q", dnsAddr.String(), tt.wantDNS)
			}
		})
	}
}

func TestBuildResolvectlArgs(t *testing.T) {
	tests := []struct {
		name   string
		action string
		iface  string
		extra  []string
		want   []string
	}{
		{
			name:   "revert",
			action: "revert",
			iface:  "xray_tun",
			want:   []string{"revert", "xray_tun"},
		},
		{
			name:   "dns single",
			action: "dns",
			iface:  "xray_tun",
			extra:  []string{"192.168.100.2"},
			want:   []string{"dns", "xray_tun", "192.168.100.2"},
		},
		{
			name:   "dns multiple",
			action: "dns",
			iface:  "xray_tun",
			extra:  []string{"192.168.100.2", "fc00::2"},
			want:   []string{"dns", "xray_tun", "192.168.100.2", "fc00::2"},
		},
		{
			name:   "domain wildcard",
			action: "domain",
			iface:  "xray_tun",
			extra:  []string{"~."},
			want:   []string{"domain", "xray_tun", "~."},
		},
		{
			name:   "default-route",
			action: "default-route",
			iface:  "xray_tun",
			extra:  []string{"true"},
			want:   []string{"default-route", "xray_tun", "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildResolvectlArgs(tt.action, tt.iface, tt.extra...)
			if len(got) != len(tt.want) {
				t.Fatalf("args = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("args[%d] = %q, want %q (full: %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

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
			{Tag: "block", ProxySettings: serial.ToTypedMessage(&freedom.Config{Firewall: []*freedom.FirewallConfig{{Action: freedom.RuleAction_Block, Delay: &freedom.Range{}}}})},
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

// localNameServer is a name server pointed at "localhost", which app/dns
// resolves through the system resolver.
func localNameServer() *appdns.NameServer {
	return &appdns.NameServer{
		Address: &net.Endpoint{
			Network: net.Network_UDP,
			Address: &net.IPOrDomain{Address: &net.IPOrDomain_Domain{Domain: "localhost"}},
			Port:    53,
		},
	}
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
			// An independent upstream is not enough on its own: name servers are
			// selected per domain, so a local one can still be the one chosen.
			// The refusal is deliberately domain-agnostic for that reason.
			name:        "a local name server alongside an independent one",
			withDNSApp:  true,
			nameServers: append(udpNameServer([]byte{9, 9, 9, 9}), localNameServer()),
			rules:       []*router.RoutingRule{port53Rule()},
			wantErr:     "system resolver",
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

// Without an IPv4 gateway, the takeover uses the first IPv6 one, and the probe
// carries IPv6 addresses.
func TestVerifyDNSRoutingIPv6(t *testing.T) {
	ctx := newRouteTestContext(t, true, udpNameServer([]byte{9, 9, 9, 9}), []*router.RoutingRule{port53Rule()})
	if err := verifyDNSRouting(ctx, routeTestInboundTag, "fc00::1", "fc00::2"); err != nil {
		t.Fatalf("expected the takeover to be accepted, got: %v", err)
	}
	if err := verifyDNSRouting(ctx, routeTestInboundTag, routeTestSource, "fc00::2"); err == nil {
		t.Fatal("expected mixed IPv4 and IPv6 addresses to be refused")
	}
}
