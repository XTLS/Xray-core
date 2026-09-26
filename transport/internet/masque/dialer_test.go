package masque

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func TestUsesHTTP2(t *testing.T) {
	for _, c := range []struct {
		alpn []string
		want bool
	}{
		{alpn: nil, want: false},
		{alpn: []string{"h3"}, want: false},
		{alpn: []string{"h2"}, want: true},
		{alpn: []string{"h2", "http/1.1"}, want: true},
		{alpn: []string{"h3", "h2"}, want: false},
		{alpn: []string{"http/1.1"}, want: false},
	} {
		if got := usesHTTP2(&tls.Config{NextProtocol: c.alpn}); got != c.want {
			t.Errorf("usesHTTP2(%q) = %v, want %v", c.alpn, got, c.want)
		}
	}
}

func TestAuthority(t *testing.T) {
	for _, c := range []struct {
		host, serverName string
		port             net.Port
		want             string
	}{
		{serverName: "example.com", port: 443, want: "example.com"},
		{serverName: "example.com", port: 8443, want: "example.com:8443"},
		{serverName: "127.0.0.1", port: 443, want: "127.0.0.1"},
		{serverName: "[2001:db8::1]", port: 443, want: "[2001:db8::1]"},
		{serverName: "[2001:db8::1]", port: 8443, want: "[2001:db8::1]:8443"},
		{serverName: "2001:db8::1", port: 8443, want: "[2001:db8::1]:8443"},
		{host: "proxy.example", serverName: "example.com", port: 8443, want: "proxy.example"},
	} {
		if got := authority(&Config{Host: c.host}, c.serverName, c.port); got != c.want {
			t.Errorf("authority(%q, %q, %d) = %q, want %q", c.host, c.serverName, c.port, got, c.want)
		}
	}
}

func TestLocalAddrs(t *testing.T) {
	assigned := func(prefixes ...string) []connectip.AssignedAddress {
		var a []connectip.AssignedAddress
		for _, p := range prefixes {
			a = append(a, connectip.AssignedAddress{IPPrefix: netip.MustParsePrefix(p)})
		}
		return a
	}
	addrs := func(s ...string) []netip.Addr {
		var a []netip.Addr
		for _, v := range s {
			a = append(a, netip.MustParseAddr(v))
		}
		return a
	}
	for _, c := range []struct {
		assigned []connectip.AssignedAddress
		want     []netip.Addr
	}{
		{assigned("192.0.2.2/32", "2001:db8::2/128"), addrs("192.0.2.2", "2001:db8::2")},
		{assigned("2001:db8::/64", "192.0.2.0/24", "198.51.100.7/32"), addrs("2001:db8::1", "192.0.2.1")},
		{assigned("0.0.0.0/32", "2001:db8::2/128"), addrs("2001:db8::2")},
		{assigned("0.0.0.0/32", "::/128"), nil},
	} {
		if got := localAddrs(c.assigned); !slices.Equal(got, c.want) {
			t.Errorf("localAddrs(%v) = %v, want %v", c.assigned, got, c.want)
		}
	}
}
