package net_test

import (
	"testing"

	. "github.com/GFW-knocker/Xray-core/common/net"
)

func TestPortRangeContains(t *testing.T) {
	portRange := &PortRange{
		From: 53,
		To:   53,
	}

	if !portRange.Contains(Port(53)) {
		t.Error("expected port range containing 53, but actually not")
	}
}
