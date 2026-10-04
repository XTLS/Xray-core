package dns

import (
	"context"
	go_errors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

type scriptNameServer struct {
	name    string
	answers map[string]net.IP
	errors  map[string]error
	ttl     uint32
	calls   int
}

func (s *scriptNameServer) Name() string         { return s.name }
func (s *scriptNameServer) IsDisableCache() bool { return true }

func (s *scriptNameServer) QueryIP(ctx context.Context, domain string, _ featureDNS.IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	s.calls++
	if err := s.errors[domain]; err != nil {
		return nil, 0, err
	}
	ip, ok := s.answers[domain]
	if !ok {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	return []net.IP{ip}, s.ttl, nil
}

func TestDNSScriptQuery(t *testing.T) {
	wantIP := net.ParseIP("127.0.0.1")
	upstreamErr := go_errors.New("upstream failed")
	for _, tc := range []struct {
		name, body  string
		wantIPs     []net.IP
		wantTTL     uint32
		wantErr     error
		wantMessage string
		wantCalls   uint32
	}{
		{name: "IPs", body: `return server:Query(domain, ipv4, ipv6, fake)`, wantIPs: []net.IP{wantIP}, wantTTL: 60, wantCalls: 2},
		{name: "empty result", body: `return nil, 0`, wantErr: featureDNS.ErrEmptyResponse, wantCalls: 2},
		{name: "upstream error", body: `return server:Query("failed.example", ipv4, ipv6, fake)`, wantErr: upstreamErr, wantCalls: 2},
		{name: "string error", body: `return nil, nil, "blocked"`, wantMessage: "blocked", wantCalls: 2},
		{name: "invalid result", body: `return false, 0`, wantMessage: "native IP slice", wantCalls: 2},
		{name: "execution error", body: `error("execution failed")`, wantMessage: "execution failed", wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `
local server = require("xray.dns").Servers[1]
local calls = 0
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    calls = calls + 1
    if domain == "count.example" then
        local ips, _, err = server:Query("good.example", ipv4, ipv6, fake)
        return ips, calls, err
    end
    ` + tc.body + `
end
`
			path := filepath.Join(t.TempDir(), "query.lua")
			if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			option := featureDNS.IPOption{IPv4Enable: true}
			upstream := &scriptNameServer{
				name:    "test",
				answers: map[string]net.IP{"good.example": wantIP},
				errors:  map[string]error{"failed.example": upstreamErr},
				ttl:     60,
			}
			server := &DNS{
				ctx:     context.Background(),
				clients: []*Client{{server: upstream, ipOption: &option, timeoutMs: time.Second}},
			}
			engine, err := newScriptEngine(path, server)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.close()

			ips, ttl, err := engine.query("good.example", option)
			switch {
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Fatalf("query error = %v, want original error %v", err, tc.wantErr)
				}
			case tc.wantMessage != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
					t.Fatalf("query error = %v, want %q", err, tc.wantMessage)
				}
			case err != nil:
				t.Fatal(err)
			}
			if ttl != tc.wantTTL || len(ips) != len(tc.wantIPs) {
				t.Fatalf("query = %v, TTL %d; want %v, TTL %d", ips, ttl, tc.wantIPs, tc.wantTTL)
			}
			for i := range ips {
				if !ips[i].Equal(tc.wantIPs[i]) {
					t.Fatalf("IP %d = %v, want %v", i, ips[i], tc.wantIPs[i])
				}
			}

			ips, calls, err := engine.query("count.example", option)
			if err != nil || calls != tc.wantCalls || len(ips) != 1 || !ips[0].Equal(wantIP) {
				t.Fatalf("next query = %v, calls %d, %v; want %v, calls %d", ips, calls, err, wantIP, tc.wantCalls)
			}
		})
	}
}

func TestDNSScriptGeoIPFallback(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))
	script := `
local servers = require("xray.dns").Servers
local us_ips = require("xray.geodata").BuildIPMatcher("geoip:us")

local by_id = {}
for _, server in ipairs(servers) do
    by_id[server.ID] = server
end
assert(by_id.primary and by_id.fallback, "primary and fallback DNS servers are required")

function HandleDNSQuery(domain, ipv4, ipv6, fake)
    local ips, ttl, err = by_id.primary:Query(domain, ipv4, ipv6, fake)
    if not err and us_ips:AnyMatch(ips) then
        return ips, ttl, nil
    end
    return by_id.fallback:Query(domain, ipv4, ipv6, fake)
end
`
	scriptPath := filepath.Join(t.TempDir(), "geoip_fallback.lua")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	primary := &scriptNameServer{
		name: "primary",
		answers: map[string]net.IP{
			"us.example":    net.ParseIP("2001:4860:4860::8888"),
			"other.example": net.ParseIP("127.0.0.1"),
		},
		ttl: 30,
	}
	fallback := &scriptNameServer{
		name:    "fallback",
		answers: map[string]net.IP{"other.example": net.ParseIP("9.9.9.9")},
		ttl:     60,
	}
	option := featureDNS.IPOption{IPv4Enable: true, IPv6Enable: true}
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &DNS{
		ctx:        context.Background(),
		hosts:      hosts,
		ipOption:   &option,
		scriptPath: scriptPath,
		clients: []*Client{
			{id: "primary", server: primary, ipOption: &option, timeoutMs: 2 * time.Second},
			{id: "fallback", server: fallback, ipOption: &option, timeoutMs: 2 * time.Second},
		},
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, tc := range []struct {
		domain string
		ip     net.IP
		ttl    uint32
	}{
		{"Us.Example.", net.ParseIP("2001:4860:4860::8888"), 30},
		{"other.example", net.ParseIP("9.9.9.9"), 60},
	} {
		ips, ttl, err := server.LookupIP(tc.domain, option)
		if err != nil {
			t.Fatalf("LookupIP(%q): %v", tc.domain, err)
		}
		if ttl != tc.ttl || len(ips) != 1 || !ips[0].Equal(tc.ip) {
			t.Fatalf("LookupIP(%q) = %v, TTL %d; want %v, TTL %d", tc.domain, ips, ttl, tc.ip, tc.ttl)
		}
	}
	if primary.calls != 2 || fallback.calls != 1 {
		t.Fatalf("upstream calls: primary %d, fallback %d; want 2 and 1", primary.calls, fallback.calls)
	}
}

func TestDNSScriptRejectsInvalidStartup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"syntax", "function HandleDNSQuery("},
		{"missing hook", "value = 1"},
		{"top-level error", `error("setup failed")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "script.lua")
			if err := os.WriteFile(path, []byte(tc.script), 0o600); err != nil {
				t.Fatal(err)
			}
			server := &DNS{ctx: context.Background(), scriptPath: path}
			if err := server.Start(); err == nil {
				t.Fatal("Start accepted an invalid DNS script")
			}
			if server.script != nil {
				t.Fatal("Start retained a script engine after failure")
			}
		})
	}
}

func TestDNSScriptFakeDNSOption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.lua")
	script := `
local server = require("xray.dns").Servers[1]
local log = require("xray.log")
log.Info("DNS script loaded")
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    log.Debug("DNS query: ", domain)
    local ips, ttl, err = server:Query(domain, ipv4, ipv6, fake)
    if err then log.Error("DNS failed: ", err) end
    return ips, ttl, err
end
`
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	option := featureDNS.IPOption{IPv4Enable: true}
	hosts, err := NewStaticHosts(nil)
	if err != nil {
		t.Fatal(err)
	}
	upstream := &scriptNameServer{
		name:    "FakeDNS",
		answers: map[string]net.IP{"good.example": net.ParseIP("198.18.0.1")},
		ttl:     30,
	}
	server := &DNS{
		ctx:        context.Background(),
		hosts:      hosts,
		ipOption:   &option,
		scriptPath: path,
		clients:    []*Client{{id: "fake", server: upstream, ipOption: &option, timeoutMs: time.Second}},
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	if _, _, err := server.LookupIP("good.example", option); err != featureDNS.ErrEmptyResponse {
		t.Fatalf("FakeDNS without FakeEnable = %v, want ErrEmptyResponse", err)
	}
	if upstream.calls != 0 {
		t.Fatalf("FakeDNS was queried without FakeEnable: %d calls", upstream.calls)
	}
	withFake := featureDNS.IPOption{IPv4Enable: true, FakeEnable: true}
	ips, ttl, err := server.LookupIP("good.example", withFake)
	if err != nil || ttl != 30 || len(ips) != 1 || !ips[0].Equal(net.ParseIP("198.18.0.1")) {
		t.Fatalf("FakeDNS with FakeEnable = %v, TTL %d, %v", ips, ttl, err)
	}
	if upstream.calls != 1 {
		t.Fatalf("FakeDNS query count = %d, want 1", upstream.calls)
	}
}
