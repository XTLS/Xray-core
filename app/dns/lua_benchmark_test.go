package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

// BenchmarkLuaDNSHook isolates scalar argument bridging and a fixed return.
// It excludes upstream queries, result decoding, and state pool management.
func BenchmarkLuaDNSHook(b *testing.B) {
	L := lua.NewState()
	b.Cleanup(L.Close)
	if err := L.DoString(`
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return true
end
`); err != nil {
		b.Fatal(err)
	}
	L.SetContext(context.Background())
	option := featureDNS.IPOption{IPv4Enable: true}
	if err := callLuaQuery(L, "example.com", option); err != nil {
		b.Fatal(err)
	}
	if L.Get(-3) != lua.LTrue {
		b.Fatal("hook did not return true")
	}
	L.Pop(3)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := callLuaQuery(L, "example.com", option); err != nil {
			b.Fatal(err)
		}
		L.Pop(3)
	}
}

// BenchmarkLuaDNSQuery queries the same preselected, in-memory upstream.
// client_query compares Client.QueryIP to a preloaded server:Query hook.
// script_query additionally measures production pool and timeout management.
// These cases do not measure DNS.LookupIP server selection or network latency.
func BenchmarkLuaDNSQuery(b *testing.B) {
	ctx := context.Background()
	option := featureDNS.IPOption{IPv4Enable: true}
	ip := net.ParseIP("127.0.0.1")
	upstream := &benchmarkLuaNameServer{ips: []net.IP{ip}}
	client := &Client{server: upstream, ipOption: &option, timeoutMs: time.Second}
	server := &DNS{ctx: ctx, clients: []*Client{client}}
	const script = `
local server = require("xray.dns").Servers[1]
function HandleDNSQuery(domain, ipv4, ipv6, fake)
    return server:Query(domain, ipv4, ipv6, fake)
end
`
	L := lua.NewState()
	b.Cleanup(L.Close)
	server.registerLua(L)
	if err := L.DoString(script); err != nil {
		b.Fatal(err)
	}
	L.SetContext(ctx)

	path := filepath.Join(b.TempDir(), "query.lua")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		b.Fatal(err)
	}
	engine, err := newScriptEngine(path, server)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(engine.close)
	for _, bench := range []struct {
		name  string
		query func() ([]net.IP, uint32, error)
	}{
		{"client_query/native", func() ([]net.IP, uint32, error) {
			return client.QueryIP(ctx, "example.com", option)
		}},
		{"client_query/lua", func() ([]net.IP, uint32, error) {
			if err := callLuaQuery(L, "example.com", option); err != nil {
				return nil, 0, err
			}
			ips, ttl, err := readLuaQueryResult(L)
			L.Pop(3)
			return ips, ttl, err
		}},
		{"script_query/lua", func() ([]net.IP, uint32, error) {
			return engine.query("example.com", option)
		}},
	} {
		b.Run(bench.name, func(b *testing.B) {
			ips, ttl, err := bench.query()
			if err != nil || ttl != 60 || len(ips) != 1 || !ips[0].Equal(ip) {
				b.Fatalf("query() = %v, TTL %d, %v; want %v, TTL 60", ips, ttl, err, ip)
			}
			b.ReportAllocs()
			b.ResetTimer()
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
