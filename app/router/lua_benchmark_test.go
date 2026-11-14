package router

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	routing_session "github.com/xtls/xray-core/features/routing/session"
	lua "github.com/yuin/gopher-lua"
)

func benchmarkRouteContext(target net.Destination) *routing_session.Context {
	// Use the production context: its IP getters construct a slice per call.
	// The cached IP slices in luaRouteTestContext would undercount this cost.
	return &routing_session.Context{
		Inbound: &session.Inbound{
			Tag:    "in",
			Source: net.TCPDestination(net.LocalHostIP, 1234),
			Local:  net.TCPDestination(net.LocalHostIP, 5678),
		},
		Outbound: &session.Outbound{Target: target},
		Content:  &session.Content{Protocol: "tls"},
	}
}

func benchmarkRouteState(b *testing.B, r *Router, script string) *lua.LState {
	b.Helper()
	L := lua.NewState()
	b.Cleanup(L.Close)
	r.RegisterLua(L)
	geodata.RegisterLua(L)
	if err := L.DoString(script); err != nil {
		b.Fatal(err)
	}
	L.SetContext(context.Background())
	return L
}

// BenchmarkLuaRouteHook isolates argument bridging and a fixed-return hook.
// It excludes rules, result decoding, the state pool, and Route construction.
func BenchmarkLuaRouteHook(b *testing.B) {
	L := benchmarkRouteState(b, new(Router), `
function HandleRoute(ctx, inboundTag, sourcePort, targetPort, localPort,
    targetDomain, network, protocol, user, vlessRoute, skipDNSResolve)
    return "out", "rule"
end
`)
	ctx := benchmarkRouteContext(net.TCPDestination(net.LocalHostIP, 443))
	if err := callLuaRoute(L, ctx); err != nil {
		b.Fatal(err)
	}
	outboundTag, ruleTag, err := readLuaRouteResult(L)
	L.Pop(3)
	if err != nil || outboundTag != "out" || ruleTag != "rule" {
		b.Fatalf("hook() = %q, %q, %v", outboundTag, ruleTag, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := callLuaRoute(L, ctx); err != nil {
			b.Fatal(err)
		}
		L.Pop(3)
	}
}

// BenchmarkLuaRoute compares equivalent ordered rules on the same session.
// rules returns tags only; pick_route uses Router.PickRoute on both sides.
// All compilation, matcher construction, and pool startup are outside timing.
func BenchmarkLuaRoute(b *testing.B) {
	for _, name := range []string{"scalar", "ip", "domain", "domain_32_last"} {
		b.Run(name, func(b *testing.B) {
			config, script, ctx, wantTag, wantRule := benchmarkRouteFixture(b, name)
			native := new(Router)
			if err := native.Init(context.Background(), config, nil, nil, nil); err != nil {
				b.Fatal(err)
			}
			L := benchmarkRouteState(b, native, script)

			path := filepath.Join(b.TempDir(), "route.lua")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				b.Fatal(err)
			}
			scripted := new(Router)
			if err := scripted.Init(context.Background(), &Config{Script: path}, nil, nil, nil); err != nil {
				b.Fatal(err)
			}
			if err := scripted.Start(); err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := scripted.Close(); err != nil {
					b.Error(err)
				}
			})

			for _, bench := range []struct {
				name  string
				route func() (string, string, error)
			}{
				{"rules/native", func() (string, string, error) {
					rule, _, err := native.pickRouteInternal(ctx)
					if err != nil {
						return "", "", err
					}
					tag, err := rule.GetTag()
					return tag, rule.RuleTag, err
				}},
				{"rules/lua", func() (string, string, error) {
					if err := callLuaRoute(L, ctx); err != nil {
						return "", "", err
					}
					tag, ruleTag, err := readLuaRouteResult(L)
					L.Pop(3)
					return tag, ruleTag, err
				}},
				{"pick_route/native", func() (string, string, error) {
					return benchmarkPickRoute(native, ctx)
				}},
				{"pick_route/lua", func() (string, string, error) {
					return benchmarkPickRoute(scripted, ctx)
				}},
			} {
				b.Run(bench.name, func(b *testing.B) {
					// Validate and warm both paths before measuring steady state.
					tag, ruleTag, err := bench.route()
					if err != nil || tag != wantTag || ruleTag != wantRule {
						b.Fatalf("route() = %q, %q, %v; want %q, %q", tag, ruleTag, err, wantTag, wantRule)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						tag, ruleTag, err = bench.route()
						if err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					if tag != wantTag || ruleTag != wantRule {
						b.Fatalf("route() = %q, %q; want %q, %q", tag, ruleTag, wantTag, wantRule)
					}
				})
			}
		})
	}
}

func benchmarkPickRoute(r *Router, ctx routing.Context) (string, string, error) {
	route, err := r.PickRoute(ctx)
	if err != nil {
		return "", "", err
	}
	return route.GetOutboundTag(), route.GetRuleTag(), nil
}

func benchmarkRouteFixture(b *testing.B, name string) (*Config, string, routing.Context, string, string) {
	b.Helper()
	config := new(Config)
	ctx := benchmarkRouteContext(net.TCPDestination(net.LocalHostIP, 443))
	prelude := `local router = require("xray.router")
local geodata = require("xray.geodata")
`
	body := `if inboundTag == "in" and network == router.NetworkTCP then return "out", "rule" end`
	wantTag, wantRule := "out", "rule"
	if name == "scalar" || name == "ip" {
		rule := &RoutingRule{
			TargetTag:  &RoutingRule_Tag{Tag: wantTag},
			RuleTag:    wantRule,
			InboundTag: []string{"in"},
			Networks:   []net.Network{net.Network_TCP},
		}
		if name == "ip" {
			var err error
			rule.Ip, err = geodata.ParseIPRules([]string{"127.0.0.0/8"})
			if err != nil {
				b.Fatal(err)
			}
			prelude += `local matcher = geodata.BuildIPMatcher("127.0.0.0/8")` + "\n"
			body = `if inboundTag == "in" and network == router.NetworkTCP and matcher:AnyMatch(ctx:GetTargetIPs()) then return "out", "rule" end`
		}
		config.Rule = []*RoutingRule{rule}
	} else {
		count := 1
		if name == "domain_32_last" {
			count = 32
		}
		var rules strings.Builder
		rules.WriteString("local rules = {\n")
		for i := 0; i < count; i++ {
			domain := fmt.Sprintf("route-%d.example.com", i)
			tag, ruleTag := fmt.Sprintf("out-%d", i), fmt.Sprintf("rule-%d", i)
			domains, err := geodata.ParseDomainRules([]string{"full:" + domain}, geodata.Domain_Domain)
			if err != nil {
				b.Fatal(err)
			}
			config.Rule = append(config.Rule, &RoutingRule{
				TargetTag: &RoutingRule_Tag{Tag: tag}, RuleTag: ruleTag, Domain: domains,
			})
			fmt.Fprintf(&rules, "{geodata.BuildDomainMatcher(%q), %q, %q},\n", "full:"+domain, tag, ruleTag)
			if i == count-1 {
				ctx.Outbound.Target = net.TCPDestination(net.DomainAddress(domain), 443)
				wantTag, wantRule = tag, ruleTag
			}
		}
		rules.WriteString("}\n")
		prelude += rules.String()
		body = `for i = 1, #rules do
        local rule = rules[i]
        if rule[1]:MatchAny(targetDomain) then return rule[2], rule[3] end
    end`
	}
	script := prelude + `function HandleRoute(ctx, inboundTag, sourcePort, targetPort, localPort,
    targetDomain, network, protocol, user, vlessRoute, skipDNSResolve)
    ` + body + "\nend\n"
	return config, script, ctx, wantTag, wantRule
}
