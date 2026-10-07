package xdns

import "testing"

func TestParseResolverAddr(t *testing.T) {
	for _, tc := range []struct {
		input, protocol, addr string
	}{
		{"192.0.2.1", "udp", "192.0.2.1:53"},
		{"tcp://resolver.example", "tcp", "resolver.example:53"},
		{"dot://resolver.example", "dot", "resolver.example:853"},
		{"dot://[2001:db8::1]", "dot", "[2001:db8::1]:853"},
		{"doh://resolver.example", "doh", "https://resolver.example:443/dns-query"},
		{"doh://[2001:db8::1]:8443/a%2Fb?key=a+b", "doh", "https://[2001:db8::1]:8443/a%2Fb?key=a+b"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			cfg, err := ParseResolverAddr(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Type != tc.protocol || cfg.Addr != tc.addr {
				t.Fatalf("got %+v, want %s %s", cfg, tc.protocol, tc.addr)
			}
		})
	}
}

func TestNewResolverRequiresDialer(t *testing.T) {
	for _, cfg := range []*ResolverProto{{Type: "dot", Addr: "host:853"}, {Type: "doh", Addr: "https://host:443/dns-query"}} {
		if _, err := NewResolver(cfg, nil); err == nil {
			t.Fatal("accepted missing dialer")
		}
	}
}
