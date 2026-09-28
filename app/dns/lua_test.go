package dns

import (
	"context"
	go_errors "errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

func TestReadLuaDNSResult(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	want := []net.IP{net.ParseIP("8.8.8.8"), {127, 0, 0, 1}, net.ParseIP("::1")}
	addresses := L.NewUserData()
	addresses.Value = want
	ips, ttl, err := readLuaDNSResult(addresses, lua.LNumber(45), lua.LNil)
	if err != nil || ttl != 45 || len(ips) != len(want) {
		t.Fatalf("readLuaDNSResult() = %v, TTL %d, %v", ips, ttl, err)
	}
	for i := range want {
		if !ips[i].Equal(want[i]) {
			t.Fatalf("IP %d = %v, want %v", i, ips[i], want[i])
		}
	}
}

func TestReadLuaDNSResultValidation(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	for _, tc := range []struct {
		name   string
		change func(*[3]lua.LValue)
		want   string
	}{
		{"fractional TTL", func(v *[3]lua.LValue) { v[1] = lua.LNumber(1.5) }, "invalid TTL"},
		{"oversized TTL", func(v *[3]lua.LValue) { v[1] = lua.LNumber(4294967296) }, "invalid TTL"},
		{"negative TTL", func(v *[3]lua.LValue) { v[1] = lua.LNumber(-1) }, "invalid TTL"},
		{"NaN TTL", func(v *[3]lua.LValue) { v[1] = lua.LNumber(math.NaN()) }, "invalid TTL"},
		{"missing TTL", func(v *[3]lua.LValue) { v[1] = lua.LNil }, "invalid TTL"},
		{"string IPs", func(v *[3]lua.LValue) { v[0] = lua.LString("127.0.0.1") }, "native IP slice"},
		{"wrong userdata", func(v *[3]lua.LValue) { v[0].(*lua.LUserData).Value = net.ParseIP("127.0.0.1") }, "native IP slice"},
		{"script error", func(v *[3]lua.LValue) { v[2] = lua.LString("blocked by script") }, "blocked by script"},
		{"invalid error", func(v *[3]lua.LValue) { v[2] = lua.LTrue }, "error or string"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addresses := L.NewUserData()
			addresses.Value = []net.IP{net.ParseIP("127.0.0.1")}
			values := [3]lua.LValue{addresses, lua.LNumber(60), lua.LNil}
			tc.change(&values)
			_, _, err := readLuaDNSResult(values[0], values[1], values[2])
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("readLuaDNSResult error = %v, want %q", err, tc.want)
			}
		})
	}

	addresses := L.NewUserData()
	addresses.Value = []net.IP(nil)
	for _, empty := range []lua.LValue{addresses, lua.LNil} {
		if _, _, err := readLuaDNSResult(empty, lua.LNumber(0), lua.LNil); !go_errors.Is(err, featureDNS.ErrEmptyResponse) {
			t.Fatalf("empty result error = %v, want ErrEmptyResponse", err)
		}
	}
	wantErr := go_errors.New("upstream failed")
	errorValue := L.NewUserData()
	errorValue.Value = wantErr
	if _, _, err := readLuaDNSResult(lua.LNil, lua.LNil, errorValue); err != wantErr {
		t.Fatalf("upstream error = %v, want original error %v", err, wantErr)
	}
}

func TestCallLuaHookCancellation(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	if err := L.DoString(`function handleDNSQuery(domain, ipv4, ipv6, fake) while true do end end`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err := (&DNS{}).CallLuaHook(L, ctx, "example.com", featureDNS.IPOption{IPv4Enable: true})
	if err == nil {
		t.Fatal("CallLuaHook did not stop after context cancellation")
	}
	if L.Context() != nil {
		t.Fatal("CallLuaHook left the canceled context on the Lua state")
	}
}

func TestCallLuaHookNormalizesDomain(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	addresses := L.NewUserData()
	addresses.Value = []net.IP{net.ParseIP("127.0.0.1")}
	L.SetGlobal("ips", addresses)
	if err := L.DoString(`
		function handleDNSQuery(domain, ipv4, ipv6, fake)
			assert(domain == "example.com")
			assert(ipv4 and not ipv6 and not fake)
			return ips, 60, nil
		end
	`); err != nil {
		t.Fatal(err)
	}
	s := &DNS{}
	if _, _, err := s.CallLuaHook(L, context.Background(), "ExAmPlE.CoM", featureDNS.IPOption{IPv4Enable: true}); err != nil {
		t.Fatal(err)
	}
}

func TestCallLuaHookRestoresState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"success", `return ips, 60`, false},
		{"error", `error("failed")`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			addresses := L.NewUserData()
			addresses.Value = []net.IP{net.ParseIP("127.0.0.1")}
			L.SetGlobal("ips", addresses)
			if err := L.DoString("function handleDNSQuery() " + tc.body + " end"); err != nil {
				t.Fatal(err)
			}
			previous, cancel := context.WithCancel(context.Background())
			defer cancel()
			L.SetContext(previous)
			L.Push(lua.LTrue)
			_, _, err := (&DNS{}).CallLuaHook(L, context.Background(), "example.com", featureDNS.IPOption{IPv4Enable: true})
			if (err != nil) != tc.wantErr {
				t.Fatalf("hook error = %v, want error %t", err, tc.wantErr)
			}
			if L.Context() != previous || L.GetTop() != 1 || L.Get(1) != lua.LTrue {
				t.Fatal("hook did not restore the previous context and stack")
			}
		})
	}
}

func TestLuaDNSServerQuery(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	geodata.RegisterLua(L)
	option := featureDNS.IPOption{IPv4Enable: true}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8")}
	server := &DNS{clients: []*Client{{server: &benchmarkLuaNameServer{ips: ips}, ipOption: &option, timeoutMs: time.Second}}}
	server.RegisterLua(L)
	if err := L.DoString(`
local server = require("xray.dns").servers[1]
local matcher = require("xray.geodata").ipMatcher({"127.0.0.0/8"})
function handleDNSQuery(domain, ipv4, ipv6, fake)
    local ips, ttl, err = server:query(domain, ipv4, ipv6, fake)
    assert(type(ips) == "userdata" and not err)
    assert(matcher:anyMatch(ips))
    local matched = matcher:filterIPs(ips)
    return matched, ttl, err
end
`); err != nil {
		t.Fatal(err)
	}
	got, ttl, err := server.CallLuaHook(L, context.Background(), "example.com", option)
	if err != nil || ttl != 60 || len(got) != 1 || !got[0].Equal(ips[0]) {
		t.Fatalf("server query = %v, TTL %d, %v", got, ttl, err)
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

// BenchmarkLuaDNSHookCall isolates a preloaded Lua hook and its server:query bridge.
// The direct case measures the same DNS client without Lua.
func BenchmarkLuaDNSHookCall(b *testing.B) {
	option := featureDNS.IPOption{IPv4Enable: true}
	ip := net.ParseIP("127.0.0.1")
	upstream := &benchmarkLuaNameServer{ips: []net.IP{ip}}
	client := &Client{server: upstream, ipOption: &option, timeoutMs: time.Second}
	server := &DNS{clients: []*Client{client}}
	L := lua.NewState()
	defer L.Close()
	server.RegisterLua(L)
	if err := L.DoString(`
local server = require("xray.dns").servers[1]
function handleDNSQuery(domain, ipv4, ipv6, fake)
    return server:query(domain, ipv4, ipv6, fake)
end
`); err != nil {
		b.Fatal(err)
	}

	ctx := context.Background()
	for _, bench := range []struct {
		name  string
		query func() ([]net.IP, uint32, error)
	}{
		{"direct", func() ([]net.IP, uint32, error) { return client.QueryIP(ctx, "example.com", option) }},
		{"lua_hook", func() ([]net.IP, uint32, error) { return server.CallLuaHook(L, ctx, "example.com", option) }},
	} {
		b.Run(bench.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			var ips []net.IP
			var ttl uint32
			var err error
			for i := 0; i < b.N; i++ {
				ips, ttl, err = bench.query()
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if ttl != 60 || len(ips) != 1 || !ips[0].Equal(ip) {
				b.Fatalf("query() = %v, TTL %d; want %v, TTL 60", ips, ttl, ip)
			}
		})
	}
}
