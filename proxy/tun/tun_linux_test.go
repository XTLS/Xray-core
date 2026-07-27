package tun

import (
	"net/netip"
	"testing"
)

func TestSelectLinuxGatewayDefault(t *testing.T) {
	gateway, err := selectLinuxGateway(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != defaultLinuxGateway {
		t.Fatalf("unexpected default gateway: got %s, want %s", got, defaultLinuxGateway)
	}
}

func TestSelectLinuxGatewayDefaultEmpty(t *testing.T) {
	gateway, err := selectLinuxGateway([]string{})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != defaultLinuxGateway {
		t.Fatalf("unexpected default gateway: got %s, want %s", got, defaultLinuxGateway)
	}
}

func TestSelectLinuxGatewayConfiguredIPv4(t *testing.T) {
	gateway, err := selectLinuxGateway([]string{"10.0.0.1/24"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "10.0.0.1/24" {
		t.Fatalf("unexpected gateway: got %s, want %s", got, "10.0.0.1/24")
	}
}

func TestSelectLinuxGatewaySkipsIPv6(t *testing.T) {
	gateway, err := selectLinuxGateway([]string{"fc00::1/64", "198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "198.18.0.1/15" {
		t.Fatalf("unexpected gateway: got %s, want %s", got, "198.18.0.1/15")
	}
}

func TestSelectLinuxGatewayRequiresIPv4(t *testing.T) {
	if _, err := selectLinuxGateway([]string{"fc00::1/64"}); err == nil {
		t.Fatal("expected error for IPv6-only gateway list")
	}
}

func TestSelectLinuxGatewayInvalid(t *testing.T) {
	if _, err := selectLinuxGateway([]string{"invalid"}); err == nil {
		t.Fatal("expected error for invalid gateway")
	}
}

func TestSelectLinuxGatewayParsesCorrectly(t *testing.T) {
	gateway, err := selectLinuxGateway([]string{"198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if !gateway.Addr().Is4() {
		t.Fatal("expected IPv4 gateway")
	}
	if gateway.Bits() != 15 {
		t.Fatalf("expected /15 mask, got /%d", gateway.Bits())
	}
	if !gateway.Contains(netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("gateway should contain its own address")
	}
	if !gateway.Contains(netip.MustParseAddr("198.19.255.255")) {
		t.Fatal("gateway should contain last address in /15 range")
	}
	if gateway.Contains(netip.MustParseAddr("198.20.0.1")) {
		t.Fatal("gateway should not contain address outside /15 range")
	}
}
