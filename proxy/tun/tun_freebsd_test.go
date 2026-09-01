//go:build freebsd

package tun

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestSelectFreeBSDGatewayDefault(t *testing.T) {
	gateway, local, err := selectFreeBSDGateway(nil)
	if err != nil {
		t.Fatal(err)
	}
	if gateway != netip.MustParsePrefix(defaultFreeBSDGateway) {
		t.Fatal("expected default gateway, got ", gateway)
	}
	if local != netip.MustParseAddr("169.254.10.2") {
		t.Fatal("wrong local address: ", local)
	}
}

func TestSelectFreeBSDGatewayPicksFirstIPv4(t *testing.T) {
	gateway, local, err := selectFreeBSDGateway([]string{"fd00::1/64", "10.0.0.1/30", "10.9.9.9/24"})
	if err != nil {
		t.Fatal(err)
	}
	if gateway != netip.MustParsePrefix("10.0.0.1/30") {
		t.Fatal("wrong gateway: ", gateway)
	}
	if local != netip.MustParseAddr("10.0.0.2") {
		t.Fatal("wrong local address: ", local)
	}
}

func TestSelectFreeBSDGatewayRequiresIPv4(t *testing.T) {
	if _, _, err := selectFreeBSDGateway([]string{"fd00::1/64"}); err == nil {
		t.Fatal("expected error when no IPv4 gateway is configured")
	}
}

func TestSelectFreeBSDGatewayRejectsGarbage(t *testing.T) {
	if _, _, err := selectFreeBSDGateway([]string{"not-a-prefix"}); err == nil {
		t.Fatal("expected error for invalid gateway")
	}
}

func TestSelectFreeBSDGatewayRejectsFullPrefix(t *testing.T) {
	// 10.0.0.255/30: the "next" local address falls outside the prefix
	if _, _, err := selectFreeBSDGateway([]string{"10.0.0.255/30"}); err == nil {
		t.Fatal("expected error when no usable local address follows the gateway")
	}
}

func TestNextLocalIPv4(t *testing.T) {
	local, ok := nextLocalIPv4(netip.MustParsePrefix("169.254.10.1/30"))
	if !ok || local != netip.MustParseAddr("169.254.10.2") {
		t.Fatal("wrong local address: ", local)
	}
}

func TestBuildSystemRoutesSplitsDefault(t *testing.T) {
	routes, err := buildSystemRoutes([]string{"0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
		"16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
	}
	if len(routes) != len(expected) {
		t.Fatal("expected ", len(expected), " routes, got ", routes)
	}
	for i, want := range expected {
		if routes[i] != netip.MustParsePrefix(want) {
			t.Fatal("route ", i, ": expected ", want, ", got ", routes[i])
		}
	}
}

func TestBuildSystemRoutesSplitsDefaultIPv6(t *testing.T) {
	routes, err := buildSystemRoutes([]string{"::/0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 8 || routes[7] != netip.MustParsePrefix("8000::/1") {
		t.Fatal("unexpected v6 split: ", routes)
	}
}

func TestBuildSystemRoutesDeduplicates(t *testing.T) {
	routes, err := buildSystemRoutes([]string{"10.0.0.0/8", "10.1.2.3/8", "0.0.0.0/0", "0.0.0.0/0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 9 { // 10.0.0.0/8 once + 8 splits once
		t.Fatal("expected 9 routes, got ", routes)
	}
}

func TestBuildSystemRoutesRejectsGarbage(t *testing.T) {
	if _, err := buildSystemRoutes([]string{"10.0.0.0/33"}); err == nil {
		t.Fatal("expected error for invalid route")
	}
}

func routeMessage(dst, mask route.Addr) *route.RouteMessage {
	addrs := make([]route.Addr, unix.RTAX_NETMASK+1)
	addrs[unix.RTAX_DST] = dst
	addrs[unix.RTAX_NETMASK] = mask
	return &route.RouteMessage{Addrs: addrs}
}

func TestDefaultRouteFamilyMatchesIPv4Default(t *testing.T) {
	family, ok := defaultRouteFamily(routeMessage(&route.Inet4Addr{}, &route.Inet4Addr{}))
	if !ok || family != unix.AF_INET {
		t.Fatal("expected IPv4 default route match")
	}
}

func TestDefaultRouteFamilyMatchesIPv6Default(t *testing.T) {
	family, ok := defaultRouteFamily(routeMessage(&route.Inet6Addr{}, &route.Inet6Addr{}))
	if !ok || family != unix.AF_INET6 {
		t.Fatal("expected IPv6 default route match")
	}
}

func TestDefaultRouteFamilyRejectsNonDefault(t *testing.T) {
	if _, ok := defaultRouteFamily(routeMessage(
		&route.Inet4Addr{IP: [4]byte{10, 0, 0, 0}},
		&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}},
	)); ok {
		t.Fatal("non-default destination must not match")
	}
	if _, ok := defaultRouteFamily(routeMessage(
		&route.Inet4Addr{},
		&route.Inet4Addr{IP: [4]byte{255, 0, 0, 0}},
	)); ok {
		t.Fatal("non-zero mask must not match")
	}
}

func TestDefaultRouteFamilyRejectsShortAddrs(t *testing.T) {
	if _, ok := defaultRouteFamily(&route.RouteMessage{}); ok {
		t.Fatal("message without addresses must not match")
	}
}
