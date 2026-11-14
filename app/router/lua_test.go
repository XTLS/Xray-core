package router

import (
	"context"
	go_errors "errors"
	"runtime"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	lua "github.com/yuin/gopher-lua"
)

type luaRouteTestContext struct {
	*routing_session.Context
	sourceIPs, targetIPs, localIPs []net.IP
}

func (c *luaRouteTestContext) GetSourceIPs() []net.IP { return c.sourceIPs }
func (c *luaRouteTestContext) GetTargetIPs() []net.IP { return c.targetIPs }
func (c *luaRouteTestContext) GetLocalIPs() []net.IP  { return c.localIPs }

func newLuaRouteTestContext() *luaRouteTestContext {
	return &luaRouteTestContext{
		Context: &routing_session.Context{
			Inbound: &session.Inbound{
				Tag: "in", VlessRoute: 4321,
				Source: net.TCPDestination(net.LocalHostIP, 1234),
				Local:  net.TCPDestination(net.LocalHostIP, 5678),
				User:   &protocol.MemoryUser{Email: "user@example.com"},
			},
			Outbound: &session.Outbound{
				Target:      net.TCPDestination(net.LocalHostIP, 443),
				RouteTarget: net.TCPDestination(net.DomainAddress("MiXeD.Example."), 443),
			},
			Content: &session.Content{
				Protocol: "tls", Attributes: map[string]string{"key": "value"}, SkipDNSResolve: true,
			},
		},
		sourceIPs: []net.IP{{127, 0, 0, 2}},
		targetIPs: []net.IP{{127, 0, 0, 3}},
		localIPs:  []net.IP{{127, 0, 0, 1}},
	}
}

func newLuaRouterState(t *testing.T, script string) *lua.LState {
	t.Helper()
	r := new(Router)
	if err := r.Init(context.Background(), &Config{}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	L := lua.NewState()
	t.Cleanup(L.Close)
	r.RegisterLua(L)
	geodata.RegisterLua(L)
	if err := L.DoString(script); err != nil {
		t.Fatal(err)
	}
	return L
}

func TestLuaRouteBinding(t *testing.T) {
	L := newLuaRouterState(t, `
local router = require("xray.router")
local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.0/8")
assert(router.NetworkUnknown == 0 and router.NetworkTCP == 2)
assert(router.NetworkUDP == 3 and router.NetworkUNIX == 4)
assert(router.BuildIPMatcher == nil and router.BuildDomainMatcher == nil)
function HandleRoute(ctx, inboundTag, sourcePort, targetPort, localPort,
    targetDomain, network, protocol, user, vlessRoute, skipDNSResolve, ...)
    assert(select("#", ...) == 0)
    assert(inboundTag == "in" and sourcePort == 1234 and targetPort == 443 and localPort == 5678)
    assert(targetDomain == "mixed.example." and network == router.NetworkTCP)
    assert(protocol == "tls" and user == "user@example.com" and vlessRoute == 4321 and skipDNSResolve)
    assert(ctx.GetNetwork == nil and ctx.Context == nil)
    savedContext = ctx
    sourceIPs, targetIPs, localIPs = ctx:GetSourceIPs(), ctx:GetTargetIPs(), ctx:GetLocalIPs()
    attributes = ctx:GetAttributes()
    assert(#sourceIPs == 1 and #targetIPs == 1 and #localIPs == 1)
    assert(sourceIPs[1]:String() == "127.0.0.2" and targetIPs[1]:String() == "127.0.0.3")
    assert(localIPs[1]:String() == "127.0.0.1")
    assert(matcher:Match(sourceIPs[1]) and matcher:Match(targetIPs[1]) and matcher:Match(localIPs[1]))
    assert(matcher:AnyMatch(sourceIPs) and matcher:AnyMatch(targetIPs) and matcher:AnyMatch(localIPs))
    local matched = matcher:FilterIPs(targetIPs)
    assert(#matched == 1 and matched[1]:Equal(targetIPs[1]))
    assert(attributes.key == "value" and attributes.missing == nil)
    assert(not pcall(function() attributes.key = "changed" end))
    return "out", "rule"
end`)

	ctx := newLuaRouteTestContext()
	if err := callLuaRoute(L, ctx); err != nil {
		t.Fatal(err)
	}
	if L.GetTop() != 3 || L.Get(1) != lua.LString("out") || L.Get(2) != lua.LString("rule") || L.Get(3) != lua.LNil {
		t.Fatal("callLuaRoute did not leave the three route results on the stack")
	}
	if L.GetGlobal("savedContext").(*lua.LUserData).Value != ctx {
		t.Fatal("routing context was copied")
	}
	for _, tc := range []struct {
		name string
		want []net.IP
	}{
		{"sourceIPs", ctx.sourceIPs},
		{"targetIPs", ctx.targetIPs},
		{"localIPs", ctx.localIPs},
	} {
		got := L.GetGlobal(tc.name).(*lua.LUserData).Value.([]net.IP)
		if &got[0] != &tc.want[0] {
			t.Fatalf("%s storage was copied", tc.name)
		}
	}
	ctx.Content.Attributes["key"] = "updated"
	L.SetGlobal("expectedOS", lua.LString(runtime.GOOS))
	if err := L.DoString(`
assert(attributes.key == "updated")
assert(require("xray.router").LocalOS == expectedOS)`); err != nil {
		t.Fatal(err)
	}
}

func TestLuaRouteEmptyIPs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []net.IP
	}{
		{"nil", nil},
		{"empty", []net.IP{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := newLuaRouterState(t, `
function HandleRoute(ctx)
    for _, name in ipairs({"GetSourceIPs", "GetTargetIPs", "GetLocalIPs"}) do
        local ips = ctx[name](ctx)
        if expectNil then
            assert(ips == nil)
        else
            assert(type(ips) == "userdata" and #ips == 0)
            assert(not pcall(function() return ips[1] end))
        end
    end
    return "out"
end
`)
			L.SetGlobal("expectNil", lua.LBool(tc.ips == nil))
			ctx := newLuaRouteTestContext()
			ctx.sourceIPs, ctx.targetIPs, ctx.localIPs = tc.ips, tc.ips, tc.ips
			if err := callLuaRoute(L, ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadLuaRouteResult(t *testing.T) {
	nativeErr := go_errors.New("native failure")
	for _, tc := range []struct {
		name, values      string
		wantTag, wantRule string
		wantErr           error
		wantMessage       string
	}{
		{name: "route", values: `"out", "rule"`, wantTag: "out", wantRule: "rule"},
		{name: "no match", values: `nil`},
		{name: "empty tag", values: `""`},
		{name: "no match ignores rule", values: `nil, false`},
		{name: "empty tag ignores rule", values: `"", false`},
		{name: "missing rule", values: `"out"`, wantTag: "out"},
		{name: "invalid tag", values: `1`, wantMessage: "outboundTag"},
		{name: "invalid rule", values: `"out", false`, wantMessage: "ruleTag"},
		{name: "string error", values: `nil, nil, "script failure"`, wantMessage: "script failure"},
		{name: "native error", values: `nil, nil, nativeError`, wantErr: nativeErr},
		{name: "error overrides invalid tags", values: `false, false, nativeError`, wantErr: nativeErr},
		{name: "invalid error", values: `"out", "rule", false`, wantMessage: "error or string"},
		{name: "wrong error userdata", values: `"out", "rule", wrongError`, wantMessage: "error or string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			for name, value := range map[string]any{"nativeError": nativeErr, "wrongError": "not a native error"} {
				ud := L.NewUserData()
				ud.Value = value
				L.SetGlobal(name, ud)
			}
			fn, err := L.LoadString("return " + tc.values)
			if err != nil {
				t.Fatal(err)
			}
			if err := L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true}); err != nil {
				t.Fatal(err)
			}
			outboundTag, ruleTag, err := readLuaRouteResult(L)
			if outboundTag != tc.wantTag || ruleTag != tc.wantRule {
				t.Fatalf("result = %q, %q, %v; want %q, %q", outboundTag, ruleTag, err, tc.wantTag, tc.wantRule)
			}
			switch {
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Fatalf("error = %v, want original error", err)
				}
			case tc.wantMessage != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
					t.Fatalf("error = %v, want %q", err, tc.wantMessage)
				}
			case err != nil:
				t.Fatal(err)
			}
		})
	}
}

func TestCallLuaRouteCancellation(t *testing.T) {
	L := newLuaRouterState(t, `function HandleRoute() while true do end end`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	L.SetContext(ctx)
	if err := callLuaRoute(L, &routing_session.Context{}); err == nil {
		t.Fatal("callLuaRoute did not stop after context cancellation")
	}
	if L.Context() != ctx {
		t.Fatal("callLuaRoute changed the Lua state's context")
	}
}

func TestFindProcess(t *testing.T) {
	for _, tc := range []struct {
		name, network, target string
		targetPort            uint16
		modify                func(*luaRouteTestContext)
		wantErr               bool
	}{
		{name: "TCP", network: "tcp", target: "127.0.0.3", targetPort: 443},
		{name: "UDP", network: "udp", target: "127.0.0.3", targetPort: 443, modify: func(c *luaRouteTestContext) {
			c.Outbound.Target.Network = net.Network_UDP
		}},
		{name: "domain target", network: "tcp", modify: func(c *luaRouteTestContext) { c.targetIPs = nil }},
		{name: "missing source", modify: func(c *luaRouteTestContext) { c.sourceIPs = nil }, wantErr: true},
		{name: "unsupported network", modify: func(c *luaRouteTestContext) {
			c.Outbound.Target.Network = net.Network_UNIX
		}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newLuaRouteTestContext()
			if tc.modify != nil {
				tc.modify(ctx)
			}
			called := false
			pid, name, path, err := findProcess(ctx, func(network, source string, sourcePort uint16, target string, targetPort uint16) (int, string, string, error) {
				called = true
				if network != tc.network || source != "127.0.0.2" || sourcePort != 1234 || target != tc.target || targetPort != tc.targetPort {
					t.Fatalf("endpoints = %s %s:%d -> %s:%d", network, source, sourcePort, target, targetPort)
				}
				return 42, "process", "/path/process", nil
			})
			if tc.wantErr {
				if err == nil || called {
					t.Fatalf("findProcess = %d, %q, %q, %v", pid, name, path, err)
				}
				return
			}
			if err != nil || !called || pid != 42 || name != "process" || path != "/path/process" {
				t.Fatalf("findProcess = %d, %q, %q, %v", pid, name, path, err)
			}
		})
	}
}

var _ routing.Context = (*luaRouteTestContext)(nil)
