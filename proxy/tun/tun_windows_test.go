//go:build windows

package tun

import (
	"net"
	"testing"
)

func TestScoreWindowsInterface(t *testing.T) {
	tests := []struct {
		name        string
		ifaceName   string
		description string
		want        int
	}{
		{name: "pppoe", ifaceName: "PPPoE 2", want: 0},
		{name: "generic vpn description", ifaceName: "Ethernet 2", description: "Corporate VPN Adapter", want: -1},
		{name: "virtual product in friendly name only", ifaceName: "ZeroTier One", want: 0},

		{name: "wifi name", ifaceName: "WiFi 2", want: 1},
		{name: "wi-fi name", ifaceName: "Wi-Fi", want: 1},
		{name: "wlan name", ifaceName: "WLAN3", want: 1},
		{name: "wifi description", ifaceName: "Wireless", description: "Intel(R) WiFi 6 AX200 160MHz", want: 1},
		{name: "wireless description", ifaceName: "Network 2", description: "Qualcomm Wireless Adapter", want: 1},
		{name: "wlan description", ifaceName: "Network 3", description: "802.11 WLAN Adapter", want: 1},
		{name: "802.11 description", ifaceName: "Network 4", description: "802.11ax Adapter", want: 1},
		{name: "gbe description", ifaceName: "Ethernet 5", description: "Realtek PCIe GbE Family Controller", want: 1},
		{name: "2.5gbe description", ifaceName: "Ethernet 1", description: "Realtek Gaming USB 2.5GbE Family Controller", want: 1},
		{name: "gigabit description", ifaceName: "Ethernet 4", description: "Intel(R) Gigabit Network Connection", want: 1},
		{name: "fast ethernet description", ifaceName: "Ethernet 8", description: "USB Fast Ethernet Adapter", want: 1},
		{name: "ethernet name", ifaceName: "Ethernet 6", description: "PCIe Network Adapter", want: 1},
		{name: "ethernet without description", ifaceName: "Ethernet 3", want: 1},

		{name: "zerotier description", ifaceName: "Ethernet 2", description: "ZeroTier Port", want: -1},
		{name: "hyper-v description", ifaceName: "Ethernet 3", description: "Hyper-V Network Adapter", want: -1},
		{name: "vmware description", ifaceName: "Ethernet 4", description: "VMware Network Adapter VMnet8", want: -1},
		{name: "virtualbox description", ifaceName: "Ethernet 5", description: "VirtualBox Host-Only Ethernet Adapter", want: -1},
		{name: "tailscale description", ifaceName: "Ethernet 6", description: "Tailscale Tunnel", want: -1},
		{name: "wireguard description", ifaceName: "Ethernet 7", description: "WireGuard Tunnel", want: -1},
		{name: "vpn client description", ifaceName: "Ethernet 8", description: "Corporate VPN Client Adapter", want: -1},
		{name: "wintun description", ifaceName: "Ethernet 9", description: "Wintun Tunnel", want: -1},

		{name: "virtual takes precedence over wifi", ifaceName: "WiFi", description: "Microsoft Wi-Fi Direct Virtual Adapter", want: -1},
		{name: "vpn client takes precedence over wired", ifaceName: "Ethernet", description: "Gigabit VPN Client Adapter", want: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			iface := &net.Interface{Name: test.ifaceName}
			if got := scoreWindowsInterface(iface, test.description); got != test.want {
				t.Fatalf("scoreWindowsInterface(%q, %q) = %d, want %d", test.ifaceName, test.description, got, test.want)
			}
		})
	}
}
