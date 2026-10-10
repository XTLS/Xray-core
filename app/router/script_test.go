package router

import (
	"context"
	stdnet "net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wireDNS "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dispatcher"
	appdns "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/proxy/freedom"
)

type luaRouteDNSClient struct {
	featureDNS.Client
	lookup func(string, featureDNS.IPOption) ([]net.IP, uint32, error)
}

func (d *luaRouteDNSClient) LookupIP(domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	return d.lookup(domain, option)
}

type luaRouteOutboundManager struct{ outbound.Manager }

func (*luaRouteOutboundManager) Select(selectors []string) []string { return selectors }

func writeRouteScript(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "route.lua")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startLuaRouter(t *testing.T, script string, d featureDNS.Client, config *Config) *Router {
	t.Helper()
	if config == nil {
		config = &Config{}
	}
	config.Script = writeRouteScript(t, script)
	r := new(Router)
	if err := r.Init(context.Background(), config, d, &luaRouteOutboundManager{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func TestRouterScriptStartup(t *testing.T) {
	for _, tc := range []struct{ name, script string }{
		{"syntax error", "function HandleRoute("},
		{"missing hook", "value = 1"},
		{"initialization error", `error("setup failed")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := new(Router)
			if err := r.Init(context.Background(), &Config{Script: writeRouteScript(t, tc.script)}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			if err := r.Start(); err == nil {
				t.Fatal("Start accepted an invalid routing script")
			}
		})
	}
}

func TestRouterScriptRouting(t *testing.T) {
	for _, tc := range []struct {
		name, body        string
		wantTag, wantRule string
		wantErr           error
		wantMessage       string
		wantCalls         string
	}{
		{name: "route", body: `return "lua-out", "lua-rule"`, wantTag: "lua-out", wantRule: "lua-rule", wantCalls: "2"},
		{name: "no match", body: `return nil`, wantErr: common.ErrNoClue, wantCalls: "2"},
		{name: "empty tag", body: `return ""`, wantErr: common.ErrNoClue, wantCalls: "2"},
		{name: "balancer error", body: `local tag, err = router:PickOutbound("missing"); return tag, nil, err`, wantMessage: "not found", wantCalls: "2"},
		{name: "string error", body: `return nil, nil, "blocked"`, wantMessage: "blocked", wantCalls: "2"},
		{name: "invalid tag", body: `return false`, wantMessage: "outboundTag", wantCalls: "2"},
		{name: "invalid rule", body: `return "lua-out", false`, wantMessage: "ruleTag", wantCalls: "2"},
		{name: "execution error", body: `error("execution failed")`, wantMessage: "execution failed", wantCalls: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dnsCalls atomic.Int32
			d := &luaRouteDNSClient{lookup: func(string, featureDNS.IPOption) ([]net.IP, uint32, error) {
				dnsCalls.Add(1)
				return []net.IP{{1, 2, 3, 4}}, 60, nil
			}}
			script := `
local router = require("xray.router")
local calls = 0
function HandleRoute(ctx, inbound)
    calls = calls + 1
    if inbound == "count" then return "lua-out", tostring(calls) end
    ` + tc.body + `
end
`
			r := startLuaRouter(t, script, d, &Config{
				DomainStrategy: Config_IpOnDemand,
				Rule: []*RoutingRule{{
					TargetTag: &RoutingRule_Tag{Tag: "json-out"},
					Networks:  []net.Network{net.Network_TCP},
				}},
			})
			ctx := newLuaRouteTestContext()
			ctx.Content.SkipDNSResolve = false
			route, err := r.PickRoute(ctx)
			switch {
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Fatalf("route error = %v, want %v", err, tc.wantErr)
				}
			case tc.wantMessage != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
					t.Fatalf("route error = %v, want %q", err, tc.wantMessage)
				}
			case err != nil:
				t.Fatal(err)
			}
			if tc.wantTag == "" {
				if route != nil {
					t.Fatalf("route = %v, want nil", route)
				}
			} else if route == nil || route.GetOutboundTag() != tc.wantTag || route.GetRuleTag() != tc.wantRule || route.(*Route).Context != ctx {
				t.Fatalf("route = %v; want %q, %q and original context", route, tc.wantTag, tc.wantRule)
			}

			ctx.Inbound.Tag = "count"
			route, err = r.PickRoute(ctx)
			if err != nil || route == nil || route.GetOutboundTag() != "lua-out" || route.GetRuleTag() != tc.wantCalls {
				t.Fatalf("next route = %v, %v; want lua-out, calls %s", route, err, tc.wantCalls)
			}
			if dnsCalls.Load() != 0 {
				t.Fatal("script routing implicitly resolved DNS")
			}
		})
	}
}

func TestRouterScriptModules(t *testing.T) {
	ips := []net.IP{{127, 0, 0, 7}}
	calls := 0
	d := &luaRouteDNSClient{lookup: func(domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
		calls++
		if domain != "mixed.example." || !option.IPv4Enable || option.IPv6Enable || !option.FakeEnable {
			t.Fatalf("dns.Query arguments = %q, %+v", domain, option)
		}
		return ips, 17, nil
	}}
	r := startLuaRouter(t, `
local dns = require("xray.dns")
local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.0/8")
assert(dns.Servers == nil and type(dns.Query) == "function")
assert(type(require("xray.log").Info) == "function")
function HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, domain)
    local ips, ttl, err = dns.Query(domain, true, false, true)
    assert(not err and ttl == 17)
    assert(matcher:AnyMatch(ips) and matcher:AnyMatch(ctx:GetTargetIPs()))
    return "out"
end`, d, nil)
	if _, err := r.PickRoute(newLuaRouteTestContext()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("DNS calls = %d, want 1", calls)
	}
}

func TestRouterScriptBalancerReload(t *testing.T) {
	config := func(tag string) *Config {
		return &Config{BalancingRule: []*BalancingRule{{
			Tag: "balance", Strategy: "roundrobin", OutboundSelector: []string{tag},
		}}}
	}
	r := startLuaRouter(t, `
local router = require("xray.router")
function HandleRoute()
    local tag, err = router:PickOutbound("balance")
    return tag, "balanced", err
end`, nil, config("old"))
	pick := func(want string) {
		t.Helper()
		route, err := r.PickRoute(&routing_session.Context{})
		if err != nil || route.GetOutboundTag() != want || route.GetRuleTag() != "balanced" {
			t.Fatalf("route = %v, %v, want %q", route, err, want)
		}
	}

	pick("old")
	if err := r.SetOverrideTarget("balance", "override"); err != nil {
		t.Fatal(err)
	}
	pick("override")
	if err := r.SetOverrideTarget("balance", ""); err != nil {
		t.Fatal(err)
	}
	if err := r.ReloadRules(config("new"), false); err != nil {
		t.Fatal(err)
	}
	pick("new")
}

func TestRouterScriptConcurrentBalancerReload(t *testing.T) {
	config := func(tag string) *Config {
		return &Config{BalancingRule: []*BalancingRule{{
			Tag: "balance", Strategy: "roundrobin", OutboundSelector: []string{tag},
		}}}
	}
	r := startLuaRouter(t, `
local router = require("xray.router")
function HandleRoute()
    local tag, err = router:PickOutbound("balance")
    return tag, nil, err
end`, nil, config("a"))

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				route, err := r.PickRoute(&routing_session.Context{})
				if err != nil {
					t.Errorf("PickRoute: %v", err)
					return
				}
				if tag := route.GetOutboundTag(); tag != "a" && tag != "b" {
					t.Errorf("unexpected tag %q", tag)
				}
			}
		})
	}
	wg.Go(func() {
		for range 20 {
			for _, tag := range []string{"a", "b"} {
				if err := r.ReloadRules(config(tag), false); err != nil {
					t.Error(err)
					return
				}
			}
		}
	})
	wg.Wait()
}

func TestRouterScriptDNSDispatcherReentry(t *testing.T) {
	conn, err := stdnet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*stdnet.UDPAddr).Port
	ready, stopped := make(chan struct{}), make(chan error, 1)
	var queries atomic.Int32
	server := &wireDNS.Server{
		PacketConn: conn,
		NotifyStartedFunc: func() {
			close(ready)
		},
		Handler: wireDNS.HandlerFunc(func(w wireDNS.ResponseWriter, query *wireDNS.Msg) {
			queries.Add(1)
			response := new(wireDNS.Msg).SetReply(query)
			for _, question := range query.Question {
				if question.Name == "nested.example." && question.Qtype == wireDNS.TypeA {
					response.Answer = append(response.Answer, &wireDNS.A{
						Hdr: wireDNS.RR_Header{Name: question.Name, Rrtype: wireDNS.TypeA, Class: wireDNS.ClassINET, Ttl: 60},
						A:   stdnet.IP{127, 0, 0, 7},
					})
				}
			}
			if err := w.WriteMsg(response); err != nil {
				t.Error(err)
			}
		}),
	}
	go func() { stopped <- server.ActivateAndServe() }()
	defer func() {
		server.Shutdown()
		select {
		case err := <-stopped:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("DNS server did not stop")
		}
	}()
	select {
	case <-ready:
	case err := <-stopped:
		t.Fatalf("DNS server startup: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("DNS server did not start")
	}

	dnsScript := writeRouteScript(t, `
local server = require("xray.dns").Servers[1]
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return server:Query(domain, ipv4, ipv6, fake)
end`)
	routerScript := writeRouteScript(t, `
local router = require("xray.router")
local dns = require("xray.dns")
local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.7")
local active = false
function HandleRoute(ctx, inbound, sourcePort, targetPort, localPort, domain, network,
    protocol, user, vlessRoute, skipDNSResolve)
    assert(not active, "borrowed Router VM reentered")
    if inbound == "dns" then
        assert(network == router.NetworkUDP and skipDNSResolve == false)
        return "direct", "dns-route"
    end
    active = true
    local ips, ttl, err = dns.Query("nested.example", true, false, false)
    assert(not err and matcher:AnyMatch(ips) and active)
    active = false
    return "direct", "outer-route"
end`)
	instance, err := core.New(&core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(&appdns.Config{
				Tag: "dns", Script: dnsScript, DisableCache: true,
				NameServer: []*appdns.NameServer{{
					Id: "upstream", TimeoutMs: 1000,
					Address: &net.Endpoint{
						Network: net.Network_UDP,
						Address: &net.IPOrDomain{Address: &net.IPOrDomain_Ip{Ip: []byte{127, 0, 0, 1}}},
						Port:    uint32(port),
					},
				}},
			}),
			serial.ToTypedMessage(&Config{Script: routerScript}),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: []*core.OutboundHandlerConfig{
			{Tag: "default", ProxySettings: serial.ToTypedMessage(&blackhole.Config{})},
			{Tag: "direct", ProxySettings: serial.ToTypedMessage(&freedom.Config{
				FinalRules: []*freedom.FinalRuleConfig{{Action: freedom.RuleAction_Allow}},
			})},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatal(err)
	}
	r := instance.GetFeature(routing.RouterType()).(*Router)
	route, err := r.PickRoute(newLuaRouteTestContext())
	if err != nil || route.GetOutboundTag() != "direct" || route.GetRuleTag() != "outer-route" {
		t.Fatalf("nested DNS routing = %v, %v", route, err)
	}
	if queries.Load() == 0 {
		t.Fatal("DNS query did not pass through the dispatcher")
	}
}
