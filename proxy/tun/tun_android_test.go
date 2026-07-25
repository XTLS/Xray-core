//go:build android

package tun

import (
	"net"
	"net/netip"
	"testing"
)

// androidRoutes uses simplified signature (no unused gateway params)
func TestAndroidRoutes(t *testing.T) {
	t.Run("routes go to custom table 2022", func(t *testing.T) {
		routes, err := androidRoutes([]string{"0.0.0.0/0", "::/0"}, 2022, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) == 0 {
			t.Fatal("expected at least one route")
		}
		for i, r := range routes {
			if r.Table != 2022 {
				t.Errorf("route[%d] table=%d, want 2022", i, r.Table)
			}
		}
	})

	t.Run("routes for IPv4 only", func(t *testing.T) {
		routes, err := androidRoutes([]string{"0.0.0.0/0"}, 2022, 0)
		if err != nil {
			t.Fatal(err)
		}
		hasV4 := false
		for _, r := range routes {
			if r.Dst != nil && r.Dst.IP.To4() != nil {
				hasV4 = true
			}
		}
		if !hasV4 {
			t.Error("expected at least one IPv4 route")
		}
	})

	t.Run("empty route list when no autoSystemRoutingTable", func(t *testing.T) {
		routes, err := androidRoutes([]string{}, 2022, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) != 0 {
			t.Errorf("expected 0 routes, got %d", len(routes))
		}
	})

	t.Run("route LinkIndex set via argument", func(t *testing.T) {
		routes, err := androidRoutes([]string{"0.0.0.0/0"}, 2022, 42)
		if err != nil {
			t.Fatal(err)
		}
		if len(routes) > 0 && routes[0].LinkIndex != 42 {
			t.Errorf("LinkIndex=%d, want 42", routes[0].LinkIndex)
		}
	})

	t.Run("invalid CIDR returns error", func(t *testing.T) {
		_, err := androidRoutes([]string{"bad/prefix"}, 2022, 0)
		if err == nil {
			t.Error("expected error for invalid CIDR")
		}
	})
}

// prefixToIPNet helper
func TestPrefixToIPNet(t *testing.T) {
	t.Run("converts IPv4 prefix", func(t *testing.T) {
		got := prefixToIPNet(netip.MustParsePrefix("198.18.0.1/24"))
		if got == nil {
			t.Fatal("got nil")
		}
		if !got.IP.Equal(net.ParseIP("198.18.0.1")) {
			t.Errorf("IP=%s, want 198.18.0.1", got.IP)
		}
		ones, bits := got.Mask.Size()
		if ones != 24 || bits != 32 {
			t.Errorf("Mask=%d/%d, want 24/32", ones, bits)
		}
	})

	t.Run("converts IPv6 prefix", func(t *testing.T) {
		got := prefixToIPNet(netip.MustParsePrefix("fc00::1/126"))
		if got == nil {
			t.Fatal("got nil")
		}
		ones, bits := got.Mask.Size()
		if ones != 126 || bits != 128 {
			t.Errorf("Mask=%d/%d, want 126/128", ones, bits)
		}
	})
}
