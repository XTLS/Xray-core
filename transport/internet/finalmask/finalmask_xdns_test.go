package finalmask_test

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"github.com/xtls/xray-core/transport/internet/finalmask/xicmp"
)

func TestXDNSEncryptedDialOwnership(t *testing.T) {
	for _, masks := range [][]finalmask.UDPMask{
		{&xdns.Config{Resolvers: []*xdns.ResolverProto{{Type: "dot", Addr: "host:853"}}}},
		{&xdns.Config{Resolvers: []*xdns.ResolverProto{{Type: "doh", Addr: "https://host:443/dns-query"}}}, &xicmp.Config{}},
		{&xicmp.Config{}, &xdns.Config{Resolvers: []*xdns.ResolverProto{{Type: "dot", Addr: "host:853"}}}},
	} {
		dials := 0
		fm := finalmask.NewFinalMask(nil, masks, nil, nil,
			func(context.Context, net.Destination) (net.PacketConn, net.Addr, error) {
				dials++
				t.Fatal("opened an unnecessary outer socket")
				return nil, nil, nil
			}, nil)
		if _, err := fm.DialUDP(context.Background(), net.UDPDestination(net.LocalHostIP, 53)); err == nil {
			t.Fatal("invalid config did not fail")
		}
		if dials != 0 {
			t.Fatal("dialed before validation")
		}
	}
}
