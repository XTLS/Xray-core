//go:build (linux && !android) || windows

package net

import (
	"net/netip"
	"slices"
	"testing"
)

func TestLocalProxiesCandidates(t *testing.T) {
	var proxies localProxies
	for _, address := range []string{"127.0.0.1:8080", "[::1]:1080", "127.0.0.1:1080", "127.0.0.1:8080"} {
		proxies.add(netip.MustParseAddrPort(address))
	}
	for _, c := range []struct {
		local, remote string
		want          []string
	}{
		{"127.0.0.1:5000", "203.0.113.1:443", []string{"203.0.113.1:443", "127.0.0.1:8080", "127.0.0.1:1080"}},
		{"127.0.0.1:5000", "127.0.0.1:1080", []string{"127.0.0.1:1080", "127.0.0.1:8080"}},
		{"127.0.0.1:5000", "", []string{"127.0.0.1:8080", "127.0.0.1:1080"}},
		{"[::1]:5000", "[2001:db8::1]:443", []string{"[2001:db8::1]:443", "[::1]:1080"}},
		{"[::1]:5000", "203.0.113.1:443", []string{"[::1]:1080"}},
		{"192.0.2.10:5000", "203.0.113.1:443", []string{"203.0.113.1:443"}},
	} {
		var remote netip.AddrPort
		if c.remote != "" {
			remote = netip.MustParseAddrPort(c.remote)
		}
		var got []string
		for _, candidate := range proxies.candidates(netip.MustParseAddrPort(c.local), remote) {
			got = append(got, candidate.String())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("candidates(%s, %s) = %v, want %v", c.local, c.remote, got, c.want)
		}
	}
}

func TestLocalProxiesLimit(t *testing.T) {
	var proxies localProxies
	for port := range uint16(localProxyLimit + 2) {
		proxies.add(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1000+port))
	}
	if len(proxies) != localProxyLimit || proxies[0].Port() != 1000+localProxyLimit+1 {
		t.Errorf("proxies = %v, want %d addresses, the newest first", proxies, localProxyLimit)
	}
}

func TestMRUPush(t *testing.T) {
	for _, c := range []struct {
		list  []int
		value int
		want  []int
	}{
		{nil, 1, []int{1}},
		{[]int{1, 2, 3}, 2, []int{2, 1, 3}},
		{[]int{1, 2, 3}, 4, []int{4, 1, 2}},
		{[]int{1, 2, 1}, 1, []int{1, 2}},
	} {
		if got := mruPush(slices.Clone(c.list), c.value, 3); !slices.Equal(got, c.want) {
			t.Errorf("mruPush(%v, %d) = %v, want %v", c.list, c.value, got, c.want)
		}
	}
}
