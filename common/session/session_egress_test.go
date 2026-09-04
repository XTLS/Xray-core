package session

import (
	gonet "net"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestOutboundEgressSourceSnapshot(t *testing.T) {
	outbound := &Outbound{}
	outbound.SetEgressSourceFromAddr(&gonet.TCPAddr{IP: gonet.ParseIP("198.51.100.10"), Port: 47376})

	source := outbound.EgressSourceSnapshot()
	if !source.IsValid() || source.Address.IP().String() != "198.51.100.10" || source.Port != net.Port(47376) {
		t.Fatalf("unexpected egress source: %s", source.String())
	}
}

func TestSetOutboundEgressSourcePropagatesToAllOutbounds(t *testing.T) {
	first := &Outbound{}
	second := &Outbound{}
	source := net.UDPDestination(net.IPAddress(gonet.ParseIP("203.0.113.20")), 35788)

	SetOutboundEgressSource([]*Outbound{first, nil, second}, source)
	for _, outbound := range []*Outbound{first, second} {
		got := outbound.EgressSourceSnapshot()
		if got.Address.IP().String() != "203.0.113.20" || got.Port != net.Port(35788) {
			t.Fatalf("unexpected propagated egress source: %s", got.String())
		}
	}
}
