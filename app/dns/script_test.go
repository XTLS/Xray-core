package dns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
)

type geoIPScriptNameServer struct {
	name    string
	answers map[string]net.IP
	ttl     uint32
	calls   int
}

func (s *geoIPScriptNameServer) Name() string         { return s.name }
func (s *geoIPScriptNameServer) IsDisableCache() bool { return true }

func (s *geoIPScriptNameServer) QueryIP(ctx context.Context, domain string, _ featureDNS.IPOption) ([]net.IP, uint32, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	s.calls++
	ip, ok := s.answers[domain]
	if !ok {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	return []net.IP{ip}, s.ttl, nil
}

func TestDNSScriptGeoIPFallback(t *testing.T) {
	t.Setenv("xray.location.asset", filepath.Join("..", "..", "resources"))
	script := `
local servers = require("xray.dns").servers
local us_ips = require("xray.geodata").ipMatcher({"geoip:us"})

local by_id = {}
for _, server in ipairs(servers) do
    by_id[server.id] = server
end
assert(by_id.primary and by_id.fallback, "primary and fallback DNS servers are required")

function handleDNSQuery(q)
    local answer = by_id.primary:query(q)
    if not answer.error and us_ips:anyMatch(answer.ips) then
        return answer
    end
    return by_id.fallback:query(q)
end
`
	scriptPath := filepath.Join(t.TempDir(), "geoip_fallback.lua")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	primary := &geoIPScriptNameServer{
		name: "primary",
		answers: map[string]net.IP{
			"us.example":    net.ParseIP("2001:4860:4860::8888"),
			"other.example": net.ParseIP("127.0.0.1"),
		},
		ttl: 30,
	}
	fallback := &geoIPScriptNameServer{
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
		{"syntax", "function handleDNSQuery("},
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

func TestDNSScriptHookErrorAndFakeDNSOption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "script.lua")
	script := `
local server = require("xray.dns").servers[1]
local log = require("xray.log")
log.info("DNS script loaded")
function handleDNSQuery(q)
    log.debug("DNS query: ", q.domain)
    if q.domain == "bad.example" then error("script failure") end
    local answer = server:query(q)
    if answer.error then log.error("DNS failed: ", answer.error) end
    return answer
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
	upstream := &geoIPScriptNameServer{
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

	if _, _, err := server.LookupIP("bad.example", option); err == nil || !strings.Contains(err.Error(), "script failure") {
		t.Fatalf("hook failure = %v, want script failure", err)
	}
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
