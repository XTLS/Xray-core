//go:build linux && !android

package tun

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// testLink returns a minimal netlink.Link whose Attrs().Name is name, so the
// DNS helpers can be exercised without a real TUN device.
func testLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

// stubDNSRouting replaces the routing probe for the duration of a test and
// reports how many times it was consulted.
func stubDNSRouting(t *testing.T, err error) *int {
	t.Helper()
	original := verifyDNSRouting
	calls := 0
	verifyDNSRouting = func(context.Context, string, string) error {
		calls++
		return err
	}
	t.Cleanup(func() { verifyDNSRouting = original })
	return &calls
}

// recordingResolvectl captures resolvectl invocations for the duration of a test.
func recordingResolvectl(t *testing.T) *[][]string {
	t.Helper()
	original := resolvectlRunner
	calls := [][]string{}
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	t.Cleanup(func() { resolvectlRunner = original })
	return &calls
}

// failingResolvectl fails the named subcommand, succeeding otherwise.
func failingResolvectl(t *testing.T, failOn string) *[][]string {
	t.Helper()
	original := resolvectlRunner
	calls := [][]string{}
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		if len(args) > 0 && args[0] == failOn {
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
			Name:          "xray_tun",
			Gateway:       []string{"192.168.100.1/30"},
			AutoSystemDns: true,
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
	calls := recordingResolvectl(t)

	t1 := optedInTun()
	t1.options.AutoSystemDns = false

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *probes != 0 {
		t.Errorf("routing probe must not run when disabled, got %d calls", *probes)
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
	calls := recordingResolvectl(t)

	t1 := optedInTun()
	t1.options.Gateway = nil

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when no IPv4 gateway is configured")
	}
	if *probes != 0 {
		t.Errorf("routing probe must not run without a gateway, got %d calls", *probes)
	}
	if len(*calls) != 0 {
		t.Errorf("resolvectl must not run without a gateway, got %v", *calls)
	}
}

// This is the case the reviewer flagged: without a routed DNS path, pointing the
// system resolver at the derived address would break resolution outright.
func TestConfigureSystemDNSLeavesOSDNSWhenNoRoute(t *testing.T) {
	probes := stubDNSRouting(t, errors.New("no route"))
	calls := recordingResolvectl(t)

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when the DNS path is unverified")
	}
	if *probes != 1 {
		t.Errorf("routing probe should run once, got %d", *probes)
	}
	if len(*calls) != 0 {
		t.Errorf("system DNS must be left untouched, got %v", *calls)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false when the path is unverified")
	}
}

func TestConfigureSystemDNSAppliesResolvectl(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recordingResolvectl(t)

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
	calls := recordingResolvectl(t)

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
	calls := failingResolvectl(t, "domain")

	t1 := optedInTun()

	if err := t1.ConfigureSystemDNS(context.Background(), "tun"); err == nil {
		t.Fatal("expected an error when a resolvectl step fails")
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false after a failed takeover")
	}
	if !strings.Contains(joined(*calls), "resolvectl revert xray_tun") {
		t.Errorf("expected a revert after partial failure, got %q", joined(*calls))
	}
}

func TestUnsetSystemDNSReverts(t *testing.T) {
	stubDNSRouting(t, nil)
	calls := recordingResolvectl(t)

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

func TestSystemDNSAddress(t *testing.T) {
	tests := []struct {
		name    string
		gateway []string
		want    string
		wantOK  bool
	}{
		{
			name:    "ipv4 /30",
			gateway: []string{"192.168.100.1/30"},
			want:    "192.168.100.2",
			wantOK:  true,
		},
		{
			name:    "ipv4 /16",
			gateway: []string{"10.0.0.1/16"},
			want:    "10.0.0.2",
			wantOK:  true,
		},
		{
			name:    "first ipv4 wins",
			gateway: []string{"fc00::1/64", "172.18.0.1/30"},
			want:    "172.18.0.2",
			wantOK:  true,
		},
		{
			name:    "no gateway",
			gateway: nil,
			want:    "",
			wantOK:  false,
		},
		{
			name:    "ipv6 only",
			gateway: []string{"fc00::1/64"},
			want:    "",
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := systemDNSAddress(tt.gateway)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("address = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildResolvectlArgs(t *testing.T) {
	tests := []struct {
		name   string
		action string
		iface  string
		dns    []string
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
			dns:    []string{"192.168.100.2"},
			want:   []string{"dns", "xray_tun", "192.168.100.2"},
		},
		{
			name:   "dns multiple",
			action: "dns",
			iface:  "xray_tun",
			dns:    []string{"192.168.100.2", "fc00::2"},
			want:   []string{"dns", "xray_tun", "192.168.100.2", "fc00::2"},
		},
		{
			name:   "domain wildcard",
			action: "domain",
			iface:  "xray_tun",
			dns:    []string{"~."},
			want:   []string{"domain", "xray_tun", "~."},
		},
		{
			name:   "default-route",
			action: "default-route",
			iface:  "xray_tun",
			dns:    []string{"true"},
			want:   []string{"default-route", "xray_tun", "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildResolvectlArgs(tt.action, tt.iface, tt.dns...)
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
