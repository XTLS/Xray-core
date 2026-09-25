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
		assert(matcher:Match(ip))
		assert(matcher:AnyMatch({ip}))
		assert(matcher:Matches({ip}))
		local matched, unmatched = matcher:FilterIPs({ip})
		assert(#matched == 1 and #unmatched == 0)
		assert(matcher:Match(matched[1]))
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
		assert(matcher:MatchAny("example.com"))
		assert(matcher:MatchAny("www.example.com"))
		assert(#(matcher:Match("www.example.com")) == 1)
	`); err != nil {
		t.Fatal(err)
	}
}
