package dns

import (
	"context"
	"testing"

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
