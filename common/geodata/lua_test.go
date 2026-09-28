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
		local matcher = require("xray.geodata").ipMatcher("127.0.0.0/8", "::1")
		assert(matcher:match(ip))
		assert(matcher:anyMatch(ips))
		assert(not matcher:matches(ips))
		local matched, unmatched = matcher:filterIPs(ips)
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
		local matcher = require("xray.geodata").domainMatcher("example.com", "full:other.com")
		assert(matcher:matchAny("example.com"))
		assert(matcher:matchAny("www.example.com"))
		assert(matcher:matchAny("other.com"))
		assert(not matcher:matchAny("www.other.com"))
		assert(#(matcher:match("www.example.com")) == 1)
	`); err != nil {
		t.Fatal(err)
	}
}

func TestLuaMatchersRejectInvalidRules(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"IP rule", `require("xray.geodata").ipMatcher("not-an-ip")`},
		{"non-string domain rule", `require("xray.geodata").domainMatcher("example.com", true)`},
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
