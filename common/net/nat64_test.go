package net_test

import (
	"net"
	"testing"

	. "github.com/xtls/xray-core/common/net"
)

func TestFilterNAT64(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("64:ff9b::1.2.3.4"),
		net.ParseIP("64:ff9b:1::5"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("1.2.3.4"),
		net.ParseIP("64:ff9b:2::1"),
	}
	got := FilterNAT64(ips)
	if len(got) != 3 || !got[0].Equal(ips[2]) || !got[1].Equal(ips[3]) || !got[2].Equal(ips[4]) {
		t.Fatalf("unexpected result: %v", got)
	}
	if got := FilterNAT64([]net.IP{ips[0]}); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}
