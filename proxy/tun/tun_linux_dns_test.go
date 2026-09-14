//go:build linux && !android

package tun

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

// testLink returns a minimal netlink.Link whose Attrs().Name is name, so
// setSystemDNS/unsetSystemDNS can be exercised without a real TUN device.
func testLink(name string) netlink.Link {
	return &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}
}

func TestSetSystemDNSNoGateway(t *testing.T) {
	t1 := &LinuxTun{options: &Config{Name: "xray_tun"}}
	if err := t1.setSystemDNS(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should be false with no IPv4 gateway")
	}
}

func TestSetSystemDNSMissingResolvectl(t *testing.T) {
	original := resolvectlRunner
	defer func() { resolvectlRunner = original }()
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		return nil, exec.ErrNotFound
	}

	t1 := &LinuxTun{options: &Config{
		Name:    "xray_tun",
		Gateway: []string{"192.168.100.1/30"},
	}, tunLink: testLink("xray_tun")}
	if err := t1.setSystemDNS(); err != nil {
		t.Fatalf("missing resolvectl must not fail Start: %v", err)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should stay false when resolvectl is unavailable")
	}
}

func TestSetSystemDNSCallsResolvectl(t *testing.T) {
	original := resolvectlRunner
	defer func() { resolvectlRunner = original }()

	var calls [][]string
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}

	t1 := &LinuxTun{options: &Config{
		Name:    "xray_tun",
		Gateway: []string{"192.168.100.1/30"},
	}, tunLink: testLink("xray_tun")}
	if err := t1.setSystemDNS(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !t1.systemDNSSet {
		t.Fatal("systemDNSSet should be true after successful set")
	}
	before := len(calls)
	if err := t1.setSystemDNS(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != before {
		t.Errorf("setSystemDNS not idempotent: %d -> %d calls", before, len(calls))
	}

	want := [][]string{
		{"resolvectl", "dns", "xray_tun", "192.168.100.2"},
		{"resolvectl", "domain", "xray_tun", "~."},
		{"resolvectl", "default-route", "xray_tun", "true"},
	}
	if len(calls) != len(want) {
		t.Fatalf("got %d calls, want %d: %v", len(calls), len(want), calls)
	}
	for i := range want {
		if strings.Join(calls[i], " ") != strings.Join(want[i], " ") {
			t.Errorf("call %d = %v, want %v", i, calls[i], want[i])
		}
	}
}

func TestUnsetSystemDNSReverts(t *testing.T) {
	original := resolvectlRunner
	defer func() { resolvectlRunner = original }()

	var calls [][]string
	resolvectlRunner = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}

	t1 := &LinuxTun{options: &Config{
		Name:    "xray_tun",
		Gateway: []string{"192.168.100.1/30"},
	}, tunLink: testLink("xray_tun")}
	if err := t1.setSystemDNS(); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	calls = nil
	if err := t1.unsetSystemDNS(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if t1.systemDNSSet {
		t.Error("systemDNSSet should be false after unset")
	}
	if len(calls) != 1 || strings.Join(calls[0], " ") != "resolvectl revert xray_tun" {
		t.Errorf("got %v, want [resolvectl revert xray_tun]", calls)
	}

	if err := t1.unsetSystemDNS(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("unsetSystemDNS not idempotent: %v", calls)
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
