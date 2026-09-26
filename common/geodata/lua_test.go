package geodata

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	lua "github.com/yuin/gopher-lua"
)

func TestLuaIPMatcherAcceptsNativeIP(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	ip := L.NewUserData()
	ip.Value = net.ParseIP("127.0.0.1")
	L.SetGlobal("ip", ip)
	if err := L.DoString(`
		local matcher = require("xray.geodata").ipMatcher({"127.0.0.0/8"})
		assert(matcher:match(ip))
		assert(matcher:anyMatch({ip}))
		assert(matcher:matches({ip}))
		local matched, unmatched = matcher:filterIPs({ip})
		assert(#matched == 1 and #unmatched == 0)
		assert(matcher:match(matched[1]))
	`); err != nil {
		t.Fatal(err)
	}
}

func TestLuaDomainMatcherUsesNativeMatcher(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	if err := L.DoString(`
		local matcher = require("xray.geodata").domainMatcher({"example.com"})
		assert(matcher:matchAny("example.com"))
		assert(matcher:matchAny("www.example.com"))
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
		{"IP rule", `require("xray.geodata").ipMatcher({"not-an-ip"})`},
		{"non-string domain rule", `require("xray.geodata").domainMatcher({true})`},
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
