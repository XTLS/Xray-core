package dns

import (
	"context"
	go_errors "errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	lua "github.com/yuin/gopher-lua"
)

func TestReadLuaQueryResult(t *testing.T) {
	wantIPs := []net.IP{net.ParseIP("8.8.8.8"), {127, 0, 0, 1}, net.ParseIP("::1")}
	nativeErr := go_errors.New("upstream failed")
	for _, tc := range []struct {
		name, values string
		wantIPs      []net.IP
		wantTTL      uint32
		wantErr      error
		wantMessage  string
	}{
		{name: "IPs", values: `ips, 45`, wantIPs: wantIPs, wantTTL: 45},
		{name: "nil IPs", values: `nil, 0`, wantErr: featureDNS.ErrEmptyResponse},
		{name: "empty IPs", values: `emptyIPs, 0`, wantErr: featureDNS.ErrEmptyResponse},
		{name: "native error", values: `nil, nil, nativeError`, wantErr: nativeErr},
		{name: "string error", values: `nil, nil, "blocked"`, wantMessage: "blocked"},
		{name: "fractional TTL", values: `ips, 1.5`, wantMessage: "invalid TTL"},
		{name: "oversized TTL", values: `ips, 4294967296`, wantMessage: "invalid TTL"},
		{name: "negative TTL", values: `ips, -1`, wantMessage: "invalid TTL"},
		{name: "NaN TTL", values: `ips, 0/0`, wantMessage: "invalid TTL"},
		{name: "missing TTL", values: `ips`, wantMessage: "invalid TTL"},
		{name: "string IPs", values: `"127.0.0.1", 60`, wantMessage: "native IP slice"},
		{name: "wrong userdata", values: `ip, 60`, wantMessage: "native IP slice"},
		{name: "invalid error", values: `ips, 60, false`, wantMessage: "error or string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			for name, value := range map[string]any{"ips": wantIPs, "ip": wantIPs[0], "emptyIPs": []net.IP(nil), "nativeError": nativeErr} {
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
			ips, ttl, err := readLuaQueryResult(L)
			switch {
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Fatalf("error = %v, want original error %v", err, tc.wantErr)
				}
			case tc.wantMessage != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantMessage) {
					t.Fatalf("error = %v, want %q", err, tc.wantMessage)
				}
			case err != nil:
				t.Fatal(err)
			}
			if ttl != tc.wantTTL || len(ips) != len(tc.wantIPs) {
				t.Fatalf("result = %v, TTL %d; want %v, TTL %d", ips, ttl, tc.wantIPs, tc.wantTTL)
			}
			for i := range ips {
				if !ips[i].Equal(tc.wantIPs[i]) {
					t.Fatalf("IP %d = %v, want %v", i, ips[i], tc.wantIPs[i])
				}
			}
			if len(ips) != 0 && &ips[0] != &tc.wantIPs[0] {
				t.Fatal("result copied the IP slice")
			}
		})
	}
}

func TestCallLuaQueryCancellation(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	if err := L.DoString(`function HandleDNSQuery(domain, ipv4, ipv6, fake) while true do end end`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	L.SetContext(ctx)
	err := callLuaQuery(L, "example.com", featureDNS.IPOption{IPv4Enable: true})
	if err == nil {
		t.Fatal("callLuaQuery did not stop after context cancellation")
	}
	if L.Context() != ctx {
		t.Fatal("callLuaQuery changed the Lua state's context")
	}
}

func TestCallLuaQuery(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	addresses := L.NewUserData()
	addresses.Value = []net.IP{net.ParseIP("127.0.0.1")}
	L.SetGlobal("ips", addresses)
	if err := L.DoString(`
		function HandleDNSQuery(domain, ipv4, ipv6, fake)
			assert(domain == "example.com")
			assert(ipv4 and not ipv6 and not fake)
			return ips, 60, nil
		end
	`); err != nil {
		t.Fatal(err)
	}
	if err := callLuaQuery(L, "ExAmPlE.CoM", featureDNS.IPOption{IPv4Enable: true}); err != nil {
		t.Fatal(err)
	}
	if L.GetTop() != 3 || L.Get(1) != addresses || L.Get(2) != lua.LNumber(60) || L.Get(3) != lua.LNil {
		t.Fatal("callLuaQuery did not leave the three query results on the stack")
	}
}

func TestLuaDNSServerQuery(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	geodata.RegisterLua(L)
	option := featureDNS.IPOption{IPv4Enable: true}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8")}
	server := &DNS{clients: []*Client{{server: &benchmarkLuaNameServer{ips: ips}, ipOption: &option, timeoutMs: time.Second}}}
	server.registerLua(L)
	if err := L.DoString(`
local server = require("xray.dns").Servers[1]
local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.0/8")
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    local ips, ttl, err = server:Query(domain, ipv4, ipv6, fake)
    assert(type(ips) == "userdata" and not err)
    assert(#ips == 2 and ips[1]:String() == "127.0.0.1" and ips[2]:String() == "8.8.8.8")
    assert(matcher:Match(ips[1]) and not matcher:Match(ips[2]))
    assert(matcher:AnyMatch(ips))
    local matched, unmatched = matcher:FilterIPs(ips)
    assert(#matched == 1 and #unmatched == 1)
    assert(matched[1]:Equal(ips[1]) and unmatched[1]:Equal(ips[2]))
    return matched, ttl, err
end
`); err != nil {
		t.Fatal(err)
	}
	L.SetContext(context.Background())
	if err := callLuaQuery(L, "example.com", option); err != nil {
		t.Fatal(err)
	}
	got, ttl, err := readLuaQueryResult(L)
	if err != nil || ttl != 60 || len(got) != 1 || !got[0].Equal(ips[0]) {
		t.Fatalf("server query = %v, TTL %d, %v", got, ttl, err)
	}
}

type luaDNSClient struct {
	featureDNS.Client
	lookup func(string, featureDNS.IPOption) ([]net.IP, uint32, error)
}

func (c *luaDNSClient) LookupIP(domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	return c.lookup(domain, option)
}

func TestLuaDNSClientQuery(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	L.SetContext(context.Background())
	geodata.RegisterLua(L)
	want := []net.IP{{127, 0, 0, 1}, net.ParseIP("::1")}
	client := &luaDNSClient{lookup: func(domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
		if domain != "MiXeD.Example." || !option.IPv4Enable || option.IPv6Enable || !option.FakeEnable {
			t.Fatalf("dns.Query arguments = %q, %+v", domain, option)
		}
		return want, 42, nil
	}}
	RegisterLua(L, client)
	if err := L.DoString(`
local dns = require("xray.dns")
local matcher = require("xray.geodata").BuildIPMatcher("127.0.0.1")
assert(dns.Servers == nil)
ips, ttl, err = dns.Query("MiXeD.Example.", true, false, true)
assert(not err and ttl == 42 and matcher:AnyMatch(ips))
assert(#ips == 2 and ips[1]:String() == "127.0.0.1" and ips[2]:String() == "::1")
assert(matcher:Match(ips[1]) and not matcher:Match(ips[2]))
`); err != nil {
		t.Fatal(err)
	}
	got := L.GetGlobal("ips").(*lua.LUserData).Value.([]net.IP)
	if &got[0] != &want[0] {
		t.Fatal("dns.Query copied the IP slice")
	}
}

func TestLuaDNSLocalClient(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	L.SetContext(context.Background())
	RegisterLua(L, localdns.New())
	if err := L.DoString(`
local dns = require("xray.dns")
assert(dns.Servers[1].ID == "localhost")
serverIPs, _, serverErr = dns.Servers[1]:Query("127.0.0.1", true, false, false)
clientIPs, _, clientErr = dns.Query("127.0.0.1", true, false, false)
assert(not serverErr and not clientErr)
assert(#serverIPs == 1 and #clientIPs == 1)
assert(serverIPs[1]:String() == "127.0.0.1" and serverIPs[1]:Equal(clientIPs[1]))
`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"serverIPs", "clientIPs"} {
		ips := L.GetGlobal(name).(*lua.LUserData).Value.([]net.IP)
		if len(ips) != 1 || !ips[0].Equal(net.ParseIP("127.0.0.1")) {
			t.Fatalf("%s = %v", name, ips)
		}
	}
}

func TestLuaDNSQueryEmptyIPs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []net.IP
	}{
		{"nil", nil},
		{"empty", []net.IP{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			L.SetContext(context.Background())
			L.SetGlobal("expectNil", lua.LBool(tc.ips == nil))
			client := &luaDNSClient{lookup: func(string, featureDNS.IPOption) ([]net.IP, uint32, error) {
				return tc.ips, 0, featureDNS.ErrEmptyResponse
			}}
			registerLua(L, []luaDNSServer{{query: func(_ context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
				return client.LookupIP(domain, option)
			}}}, client)
			if err := L.DoString(`
local dns = require("xray.dns")
for _, query in ipairs({
    function() return dns.Servers[1]:Query("empty.example", true, false, false) end,
    function() return dns.Query("empty.example", true, false, false) end,
}) do
    local ips, ttl, err = query()
    assert(ttl == 0 and err)
    if expectNil then
        assert(ips == nil)
    else
        assert(type(ips) == "userdata" and #ips == 0)
        assert(not pcall(function() return ips[1] end))
    end
end
`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type benchmarkLuaNameServer struct {
	ips []net.IP
}

func (*benchmarkLuaNameServer) Name() string         { return "benchmark" }
func (*benchmarkLuaNameServer) IsDisableCache() bool { return true }
func (s *benchmarkLuaNameServer) QueryIP(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error) {
	return s.ips, 60, nil
}
