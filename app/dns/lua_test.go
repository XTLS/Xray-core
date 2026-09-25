package dns

import (
	"context"
	go_errors "errors"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

func TestDecodeLuaDNSResultNativeIP(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	ip := net.ParseIP("127.0.0.1")
	address := L.NewUserData()
	address.Value = ip
	addresses := L.NewTable()
	addresses.RawSetInt(1, address)
	result := L.NewTable()
	result.RawSetString("ips", addresses)
	result.RawSetString("ttl", lua.LNumber(60))
	got, ttl, err := decodeLuaDNSResult(result, featureDNS.IPOption{IPv4Enable: true})
	if err != nil || ttl != 60 || len(got) != 1 || !got[0].Equal(ip) {
		t.Fatalf("decodeLuaDNSResult() = %v, %d, %v", got, ttl, err)
	}
	addresses.RawSetInt(1, lua.LString("127.0.0.1"))
	if _, _, err := decodeLuaDNSResult(result, featureDNS.IPOption{IPv4Enable: true}); err == nil {
		t.Fatal("decodeLuaDNSResult accepted a string IP")
	}
}

func TestDecodeLuaDNSResultNativeSliceCopiesIP(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	original := net.ParseIP("8.8.8.8")
	addresses := L.NewUserData()
	addresses.Value = []net.IP{original}
	result := L.NewTable()
	result.RawSetString("ips", addresses)
	result.RawSetString("ttl", lua.LNumber(45))
	ips, ttl, err := decodeLuaDNSResult(result, featureDNS.IPOption{IPv4Enable: true})
	if err != nil || ttl != 45 || len(ips) != 1 || !ips[0].Equal(original) {
		t.Fatalf("decodeLuaDNSResult() = %v, TTL %d, %v", ips, ttl, err)
	}
	original[len(original)-1] = 9
	if !ips[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("decoded IP changed with input: %v", ips[0])
	}
}

func TestDecodeLuaDNSResultValidation(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	option := featureDNS.IPOption{IPv4Enable: true}

	for _, tc := range []struct {
		name   string
		change func(*lua.LTable, *lua.LTable)
		want   string
	}{
		{"fractional TTL", func(result, _ *lua.LTable) { result.RawSetString("ttl", lua.LNumber(1.5)) }, "invalid TTL"},
		{"oversized TTL", func(result, _ *lua.LTable) { result.RawSetString("ttl", lua.LNumber(4294967296)) }, "invalid TTL"},
		{"string address", func(_, addresses *lua.LTable) { addresses.RawSetInt(1, lua.LString("127.0.0.1")) }, "invalid address"},
		{"missing addresses", func(result, _ *lua.LTable) { result.RawSetString("ips", lua.LString("127.0.0.1")) }, "must be an array"},
		{"script error", func(result, _ *lua.LTable) { result.RawSetString("error", lua.LString("blocked by script")) }, "blocked by script"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address := L.NewUserData()
			address.Value = net.ParseIP("127.0.0.1")
			addresses := L.NewTable()
			addresses.RawSetInt(1, address)
			result := L.NewTable()
			result.RawSetString("ips", addresses)
			result.RawSetString("ttl", lua.LNumber(60))
			tc.change(result, addresses)
			_, _, err := decodeLuaDNSResult(result, option)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decodeLuaDNSResult error = %v, want %q", err, tc.want)
			}
		})
	}

	address := L.NewUserData()
	address.Value = net.ParseIP("127.0.0.1")
	addresses := L.NewTable()
	addresses.RawSetInt(1, address)
	result := L.NewTable()
	result.RawSetString("ips", addresses)
	result.RawSetString("ttl", lua.LNumber(60))
	if _, _, err := decodeLuaDNSResult(result, featureDNS.IPOption{IPv6Enable: true}); err == nil {
		t.Fatal("decodeLuaDNSResult accepted IPv4 with IPv6-only option")
	}
	result.RawSetString("ips", L.NewTable())
	if _, _, err := decodeLuaDNSResult(result, option); !go_errors.Is(err, featureDNS.ErrEmptyResponse) {
		t.Fatalf("empty result error = %v, want ErrEmptyResponse", err)
	}
}

func TestCallLuaHookCancellation(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	if err := L.DoString(`function handleDNSQuery(q) while true do end end`); err != nil {
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
	address := L.NewUserData()
	address.Value = net.ParseIP("127.0.0.1")
	L.SetGlobal("ip", address)
	if err := L.DoString(`
		function handleDNSQuery(q)
			assert(type(q) == "table")
			assert(q.domain == "example.com")
			assert(q.ipv4 and not q.ipv6 and not q.fake)
			assert(q.ctx == nil)
			return {ips = {ip}, ttl = 60}
		end
	`); err != nil {
		t.Fatal(err)
	}
	s := &DNS{}
	if _, _, err := s.CallLuaHook(L, context.Background(), "ExAmPlE.CoM", featureDNS.IPOption{IPv4Enable: true}); err != nil {
		t.Fatal(err)
	}
}
