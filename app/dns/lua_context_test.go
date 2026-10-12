package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	lua "github.com/yuin/gopher-lua"
)

type luaContextDNSClient struct { *luaDNSClient; lookupContext func(context.Context,string,featureDNS.IPOption)([]net.IP,uint32,error) }
func (c *luaContextDNSClient) LookupIPContext(ctx context.Context, domain string, option featureDNS.IPOption)([]net.IP,uint32,error) { return c.lookupContext(ctx, domain, option) }

func TestLuaDNSClientUsesOptionalContext(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	ctx := context.WithValue(t.Context(), dnsContextTestKey{}, "request")
	L.SetContext(ctx)
	client := &luaContextDNSClient{
		luaDNSClient: &luaDNSClient{lookup: func(string,featureDNS.IPOption)([]net.IP,uint32,error) { t.Error("Lua used legacy lookup despite context support"); return nil, 0, featureDNS.ErrEmptyResponse }},
		lookupContext: func(received context.Context, domain string, option featureDNS.IPOption)([]net.IP,uint32,error) {
			if received.Value(dnsContextTestKey{}) != "request" || domain != "context.invalid" || !option.IPv4Enable { t.Error("Lua lost query context or arguments") }
			return []net.IP{{127,0,0,1}}, 60, nil
		},
	}
	RegisterLua(L, client)
	if err := L.DoString(`local ips, ttl, err = require("xray.dns").Query("context.invalid", true, false, false)
assert(ips and not err and ttl == 60 and #ips == 1)`); err != nil { t.Fatal(err) }
}

func TestLuaLocalDNSQueriesCancelSystemResolver(t *testing.T) {
	for _, query := range []string{
		`require("xray.dns").Query("lua-context.xdns-test.invalid", true, false, false)`,
		`require("xray.dns").Servers[1]:Query("lua-context.xdns-test.invalid", true, false, false)`,
	} {
		t.Run(query, func(t *testing.T) {
			started, canceled, stop := dnsContextSystemResolver(t)
			ctx, cancel := context.WithCancel(t.Context())
			L := lua.NewState()
			L.SetContext(ctx)
			RegisterLua(L, localdns.New())
			done, finished := make(chan error, 1), make(chan struct{})
			defer func() {
				cancel(); stop()
				select { case <-finished: L.Close(); case <-time.After(time.Second): t.Error("Lua query worker did not exit") }
			}()
			go func() { defer close(finished); done <- L.DoString(query) }()
			select { case <-started: case <-time.After(time.Second): t.Fatal("Lua did not enter local system resolver") }
			cancel()
			select { case err := <-done: if err == nil || !strings.Contains(err.Error(), "context canceled") { t.Fatalf("canceled Lua query returned %v", err) }; case <-time.After(time.Second): t.Fatal("Lua local query ignored context") }
			select { case <-canceled: case <-time.After(time.Second): t.Fatal("Lua query left local DNS worker active") }
		})
	}
}
