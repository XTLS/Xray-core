//go:build darwin

package tun

import (
	"testing"
)

func TestSelectDarwinGatewayDefault(t *testing.T) {
	gateway, err := selectDarwinGateway(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != defaultDarwinGateway {
		t.Fatalf("unexpected default gateway: got %s, want %s", got, defaultDarwinGateway)
	}
}

func TestSelectDarwinGatewayConfiguredIPv4(t *testing.T) {
	gateway, err := selectDarwinGateway([]string{"198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "198.18.0.1/15" {
		t.Fatalf("unexpected gateway: got %s", got)
	}
}

func TestSelectDarwinGatewaySkipsIPv6(t *testing.T) {
	gateway, err := selectDarwinGateway([]string{"fc00::1/64", "198.18.0.1/15"})
	if err != nil {
		t.Fatal(err)
	}
	if got := gateway.String(); got != "198.18.0.1/15" {
		t.Fatalf("unexpected gateway: got %s", got)
	}
}

func TestSelectDarwinGatewayRequiresIPv4(t *testing.T) {
	if _, err := selectDarwinGateway([]string{"fc00::1/64"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestSelectDarwinGatewayRequiresUsableLocalAddress(t *testing.T) {
	if _, err := selectDarwinGateway([]string{"198.18.0.1/32"}); err == nil {
		t.Fatal("expected error")
	}
}
