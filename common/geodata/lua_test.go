package geodata

import (
	"fmt"
	"testing"

	"github.com/xtls/xray-core/common/net"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaIPMatcher(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	ip := L.NewUserData()
	ip.Value = net.ParseIP("127.0.0.1")
	L.SetGlobal("ip", ip)
	ips := L.NewUserData()
	ips.Value = []net.IP{ip.Value.(net.IP), net.ParseIP("8.8.8.8")}
	L.SetGlobal("ips", ips)
	if err := L.DoString(`
		local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.0/8", "::1")
		assert(matcher:Match(ip))
		assert(matcher:AnyMatch(ips))
		assert(not matcher:Matches(ips))
		local matched, unmatched = matcher:FilterIPs(ips)
		assert(type(matched) == "userdata" and type(unmatched) == "userdata")
		assert(#matched == 1 and #unmatched == 1)
	`); err != nil {
		t.Fatal(err)
	}
}

func TestLuaDomainMatcher(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	if err := L.DoString(`
		local matcher = require("xray.geodata").BuildDomainMatcher("example.com", "full:other.com")
		assert(matcher:MatchAny("example.com"))
		assert(matcher:MatchAny("www.example.com"))
		assert(matcher:MatchAny("other.com"))
		assert(not matcher:MatchAny("www.other.com"))
		assert(#(matcher:Match("www.example.com")) == 1)
	`); err != nil {
		t.Fatal(err)
	}
}

func TestLuaMatchersRejectInvalidRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"IP rule", `require("xray.geodata").BuildIPMatcher("not-an-ip")`},
		{"non-string domain rule", `require("xray.geodata").BuildDomainMatcher("example.com", true)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			RegisterLua(L)
			if err := L.DoString(tc.script); err == nil {
				t.Fatal("invalid geodata rule was accepted")
			}
		})
	}
}

func TestLuaMatcherArgumentsAndAliases(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	ip := L.NewUserData()
	ip.Value = net.ParseIP("127.0.0.1")
	L.SetGlobal("ip", ip)
	if err := L.DoString(`
local geodata = require("xray.geodata")
local matcher = geodata.BuildIPMatcher("127.0.0.0/8")
assert(matcher.Match == matcher.match and matcher.AnyMatch == matcher.anyMatch)
assert(matcher.Matches == matcher.matches and matcher.FilterIPs == matcher.filterIPs)
assert(matcher:match(ip))
assert(matcher:anyMatch({ip}) and matcher:matches({ip}))
assert(not matcher:AnyMatch(nil))
assert(matcher:Matches(nil) == matcher:Matches({}))
local matched, unmatched = matcher:FilterIPs({ip})
assert(#matched == 1 and matched[1]:Equal(ip))
assert(matcher:AnyMatch(matched) and matcher:Matches(matched))
local filtered, excluded = matcher:filterIPs(matched)
assert(#filtered == 1 and #excluded == 0 and filtered[1]:Equal(ip))
local emptyMatched, emptyUnmatched = matcher:FilterIPs(nil)
assert(#emptyMatched == 0 and #emptyUnmatched == 0)
matcher:SetReverse(true)
assert(not matcher:Match(ip) and not matcher:AnyMatch(matched))
matcher:ToggleReverse()
assert(matcher:Match(ip) and matcher:AnyMatch(matched))
assert(matcher.missing == nil)

local domain = geodata.BuildDomainMatcher("full:example.com")
assert(domain.Match == domain.match and domain.MatchAny == domain.matchAny)
assert(domain:matchAny("example.com"))
assert(#domain:Match("example.com") == 1)
assert(domain:match("example.com")[1] == 0)
assert(not pcall(function() matcher:AnyMatch() end))
assert(not pcall(function() matcher:AnyMatch(matched, true) end))
assert(not pcall(function() matcher.AnyMatch(ip, matched) end))
assert(not pcall(function() matcher:Match(true) end))
assert(not pcall(function() domain:MatchAny(123) end))
assert(not pcall(function() domain:MatchAny("example.com", true) end))
assert(not pcall(function() matcher:FilterIPs(true) end))
assert(not pcall(function() matcher:FilterIPs(matched, true) end))
assert(not pcall(function() domain:Match(123) end))
assert(not pcall(function() domain:Match("example.com", true) end))
`); err != nil {
		t.Fatal(err)
	}
}

// BenchmarkLuaMatcherCall measures repeated calls with prebuilt matchers and inputs.
func BenchmarkLuaMatcherCall(b *testing.B) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	ip := net.ParseIP("127.0.0.1")
	for name, value := range map[string]any{"ip": ip, "ips": []net.IP{ip}} {
		ud := L.NewUserData()
		ud.Value = value
		L.SetGlobal(name, ud)
	}
	if err := L.DoString(`
local geodata = require("xray.geodata")
ipMatcher = geodata.BuildIPMatcher("127.0.0.0/8")
domainMatcher = geodata.BuildDomainMatcher("full:example.com")
`); err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name, expression string
	}{
		{"ip_match", "ipMatcher:Match(ip)"},
		{"ip_match_lower", "ipMatcher:match(ip)"},
		{"ip_any_match", "ipMatcher:AnyMatch(ips)"},
		{"ip_any_match_lower", "ipMatcher:anyMatch(ips)"},
		{"ip_matches", "ipMatcher:Matches(ips)"},
		{"ip_matches_lower", "ipMatcher:matches(ips)"},
		{"domain_match_any", `domainMatcher:MatchAny("example.com")`},
		{"domain_match_any_lower", `domainMatcher:matchAny("example.com")`},
		{"ip_filter", "select(1, ipMatcher:FilterIPs(ips)) ~= nil"},
		{"ip_filter_lower", "select(1, ipMatcher:filterIPs(ips)) ~= nil"},
		{"domain_match", `#domainMatcher:Match("example.com") == 1`},
		{"domain_match_lower", `#domainMatcher:match("example.com") == 1`},
		{"ip_lua_table", "ipMatcher:AnyMatch({ip})"},
		{"ip_lua_table_lower", "ipMatcher:anyMatch({ip})"},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			if err := L.DoString(fmt.Sprintf("function benchmarkMatch() return %s end", benchmark.expression)); err != nil {
				b.Fatal(err)
			}
			fn := L.GetGlobal("benchmarkMatch")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}); err != nil {
					b.Fatal(err)
				}
				if L.Get(-1) != lua.LTrue {
					b.Fatal("matcher returned false")
				}
				L.Pop(1)
			}
		})
	}
}
