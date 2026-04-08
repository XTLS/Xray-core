package geodata

import (
	"net"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/xtls/xray-core/common"
	xnet "github.com/xtls/xray-core/common/net"
)

func buildIPMatcher(rawRules ...string) IPMatcher {
	rules, err := ParseIPRules(rawRules)
	common.Must(err)

	matcher, err := newIPRegistry().BuildIPMatcher(rules)
	common.Must(err)

	return matcher
}

func sortIPStrings(ips []net.IP) []string {
	output := make([]string, 0, len(ips))
	for _, ip := range ips {
		output = append(output, ip.String())
	}
	slices.Sort(output)
	return output
}

func TestIPMatcher(t *testing.T) {
	matcher := buildIPMatcher(
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",
		"192.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"8.8.8.8/32",
		"91.108.4.0/16",
	)

	testCases := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "192.168.1.1",
			Output: true,
		},
		{
			Input:  "192.0.0.0",
			Output: true,
		},
		{
			Input:  "192.0.1.0",
			Output: false,
		},
		{
			Input:  "0.1.0.0",
			Output: true,
		},
		{
			Input:  "1.0.0.1",
			Output: false,
		},
		{
			Input:  "8.8.8.7",
			Output: false,
		},
		{
			Input:  "8.8.8.8",
			Output: true,
		},
		{
			Input:  "2001:cdba::3257:9652",
			Output: false,
		},
		{
			Input:  "91.108.255.254",
			Output: true,
		},
	}

	for _, test := range testCases {
		if v := matcher.Match(xnet.ParseAddress(test.Input).IP()); v != test.Output {
			t.Error("unexpected output: ", v, " for test case ", test)
		}
	}
}

func TestIPMatcherRegression(t *testing.T) {
	matcher := buildIPMatcher(
		"98.108.20.0/22",
		"98.108.20.0/23",
	)

	testCases := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "98.108.22.11",
			Output: true,
		},
		{
			Input:  "98.108.25.0",
			Output: false,
		},
	}

	for _, test := range testCases {
		if v := matcher.Match(xnet.ParseAddress(test.Input).IP()); v != test.Output {
			t.Error("unexpected output: ", v, " for test case ", test)
		}
	}
}

func TestIPReverseMatcher(t *testing.T) {
	matcher := buildIPMatcher(
		"8.8.8.8/32",
		"91.108.4.0/16",
	)
	matcher.SetReverse(true)

	testCases := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "8.8.8.8",
			Output: false,
		},
		{
			Input:  "2001:cdba::3257:9652",
			Output: false,
		},
		{
			Input:  "91.108.255.254",
			Output: false,
		},
	}

	for _, test := range testCases {
		if v := matcher.Match(xnet.ParseAddress(test.Input).IP()); v != test.Output {
			t.Error("unexpected output: ", v, " for test case ", test)
		}
	}
}

func TestIPReverseMatcher2(t *testing.T) {
	matcher := buildIPMatcher(
		"8.8.8.8/32",
		"91.108.4.0/16",
		"fe80::", // Keep IPv6 family non-empty so reverse matching can evaluate IPv6 input.
	)
	matcher.SetReverse(true)

	testCases := []struct {
		Input  string
		Output bool
	}{
		{
			Input:  "8.8.8.8",
			Output: false,
		},
		{
			Input:  "2001:cdba::3257:9652",
			Output: true,
		},
		{
			Input:  "91.108.255.254",
			Output: false,
		},
	}

	for _, test := range testCases {
		if v := matcher.Match(xnet.ParseAddress(test.Input).IP()); v != test.Output {
			t.Error("unexpected output: ", v, " for test case ", test)
		}
	}
}

func TestIPMatcherAnyMatchAndMatches(t *testing.T) {
	matcher := buildIPMatcher(
		"8.8.8.8/32",
		"2001:4860:4860::8888/128",
	)
	ip := func(raw string) net.IP {
		return xnet.ParseAddress(raw).IP()
	}

	if matcher.AnyMatch(nil) {
		t.Fatal("expect AnyMatch(nil) to be false")
	}

	if !matcher.AnyMatch([]net.IP{
		net.IP{},
		ip("1.1.1.1"),
		ip("8.8.8.8"),
	}) {
		t.Fatal("expect AnyMatch to ignore invalid IPs and return true when one valid IP matches")
	}

	if matcher.AnyMatch([]net.IP{
		ip("1.1.1.1"),
		ip("2001:db8::1"),
	}) {
		t.Fatal("expect AnyMatch to be false when no valid IP matches")
	}

	if !matcher.Matches([]net.IP{
		ip("8.8.8.8"),
		ip("2001:4860:4860::8888"),
	}) {
		t.Fatal("expect Matches to be true when all valid IPs match")
	}

	if matcher.Matches([]net.IP{
		ip("8.8.8.8"),
		ip("1.1.1.1"),
	}) {
		t.Fatal("expect Matches to be false when one valid IP does not match")
	}

	if matcher.Matches([]net.IP{
		ip("8.8.8.8"),
		net.IP{},
	}) {
		t.Fatal("expect Matches to be false when any IP is invalid")
	}
}

func TestIPMatcherFilterIPs(t *testing.T) {
	matcher := buildIPMatcher(
		"8.8.8.8/32",
		"91.108.4.0/16",
		"2001:4860:4860::8888/128",
	)
	ip := func(raw string) net.IP {
		return xnet.ParseAddress(raw).IP()
	}

	matched, unmatched := matcher.FilterIPs([]net.IP{
		net.IP{},
		ip("8.8.8.8"),
		ip("91.108.255.254"),
		ip("1.1.1.1"),
		ip("2001:4860:4860::8888"),
		ip("2001:db8::1"),
	})

	wantMatched := []string{
		"2001:4860:4860::8888",
		"8.8.8.8",
		"91.108.255.254",
	}
	slices.Sort(wantMatched)
	if v := sortIPStrings(matched); !reflect.DeepEqual(v, wantMatched) {
		t.Error("unexpected output: ", v, " want ", wantMatched)
	}

	wantUnmatched := []string{
		"1.1.1.1",
		"2001:db8::1",
	}
	slices.Sort(wantUnmatched)
	if v := sortIPStrings(unmatched); !reflect.DeepEqual(v, wantUnmatched) {
		t.Error("unexpected output: ", v, " want ", wantUnmatched)
	}
}

func TestIPMatcher4CN(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	matcher := buildIPMatcher("geoip:cn")

	if matcher.Match([]byte{8, 8, 8, 8}) {
		t.Error("expect CN geoip doesn't contain 8.8.8.8, but actually does")
	}
}

func TestIPMatcher6US(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	matcher := buildIPMatcher("geoip:us")

	if !matcher.Match(xnet.ParseAddress("2001:4860:4860::8888").IP()) {
		t.Error("expect US geoip contain 2001:4860:4860::8888, but actually not")
	}
}

func BenchmarkIPMatcher4CN(b *testing.B) {
	b.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	matcher := buildIPMatcher("geoip:cn")
	ip := net.IP{8, 8, 8, 8}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(ip)
	}
}

func BenchmarkIPMatcher6US(b *testing.B) {
	b.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))

	matcher := buildIPMatcher("geoip:us")
	ip := xnet.ParseAddress("2001:4860:4860::8888").IP()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = matcher.Match(ip)
	}
}
