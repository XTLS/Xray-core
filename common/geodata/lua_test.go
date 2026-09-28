package geodata

import (
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
		local matcher = require("xray.geodata").IPMatcher("127.0.0.0/8", "::1")
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
		local matcher = require("xray.geodata").DomainMatcher("example.com", "full:other.com")
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
		{"IP rule", `require("xray.geodata").IPMatcher("not-an-ip")`},
		{"non-string domain rule", `require("xray.geodata").DomainMatcher("example.com", true)`},
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
