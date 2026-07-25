//go:build android

package tun

import (
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
