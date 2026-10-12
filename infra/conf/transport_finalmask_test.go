package conf

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
)

func TestXDNSResolverEncryptedAddresses(t *testing.T) {
	for _, tc := range []struct{ input, protocol, address string }{
		{"127.0.0.1", "udp", "127.0.0.1:53"},
		{"tcp://[::1]", "tcp", "[::1]:53"},
		{"tls://resolver.test", "tls", "resolver.test:853"},
		{"quic://resolver.test", "quic", "resolver.test:853"},
		{"https://resolver.test/custom?name=one", "https", "https://resolver.test:443/custom?name=one"},
		{"https+h3://resolver.test", "https+h3", "https://resolver.test:443/dns-query"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			built, err := (&XDNS{Resolvers: []XDNSResolver{{Addrs: []string{tc.input}}}}).Build()
			if err != nil {
				t.Fatal(err)
			}
			r := built.(*xdns.Config).Resolvers[0]
			if r.Type != tc.protocol || r.Addr != tc.address {
				t.Fatalf("got %s %s; want %s %s", r.Type, r.Addr, tc.protocol, tc.address)
			}
		})
	}
}
