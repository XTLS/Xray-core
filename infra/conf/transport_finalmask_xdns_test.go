package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

func TestXDNSResolverAddrs(t *testing.T) {
	var input XDNS
	if err := json.Unmarshal([]byte(`{
		"domains": [{"names": ["one.example", "two.example"], "types": [16, 28]}],
		"resolvers": [{"addrs": ["192.0.2.1", "tcp://[2001:db8::1]:5353", "dot://resolver.example", "doh://resolver.example/custom?key=value"]}]
	}`), &input); err != nil {
		t.Fatal(err)
	}
	msg, err := input.Build()
	if err != nil {
		t.Fatal(err)
	}
	cfg := msg.(*xdns.Config)
	if len(cfg.Domains) != 2 || cfg.Domains[1].Name != "two.example" || cfg.Domains[0].Types[1] != 28 {
		t.Fatalf("domains changed: %+v", cfg.Domains)
	}
	want := []xdns.ResolverProto{
		{Type: "udp", Addr: "192.0.2.1:53"},
		{Type: "tcp", Addr: "[2001:db8::1]:5353"},
		{Type: "dot", Addr: "resolver.example:853"},
		{Type: "doh", Addr: "https://resolver.example:443/custom?key=value"},
	}
	if len(cfg.Resolvers) != len(want) {
		t.Fatalf("got %d resolvers", len(cfg.Resolvers))
	}
	for i, w := range want {
		if cfg.Resolvers[i].Type != w.Type || cfg.Resolvers[i].Addr != w.Addr {
			t.Errorf("resolver %d = %+v, want %+v", i, cfg.Resolvers[i], w)
		}
	}
}

func TestXDNSResolverInvalidAddrs(t *testing.T) {
	for _, addr := range []string{"dot://", "dot://host:0", "dot://host:65536", "dot://host/path", "dot://host?x=1", "doh://user:pass@host", "doh://host/#fragment", "doh://host:", "doh://host:bad", "doq://host", "udp://host/path"} {
		t.Run(addr, func(t *testing.T) {
			if _, err := (&XDNS{Resolvers: []XDNSResolver{{Addrs: []string{addr}}}}).Build(); err == nil {
				t.Fatalf("accepted invalid resolver %q", addr)
			}
		})
	}
}
