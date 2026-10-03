package dns

import (
	"context"
	"math"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/dns/localdns"
	lua "github.com/yuin/gopher-lua"
)

// luaDNSServer adapts configured and local DNS to the same Lua API.
type luaDNSServer struct {
	id    string
	name  string
	query func(context.Context, string, featureDNS.IPOption) ([]net.IP, uint32, error)
}

// RegisterLua makes xray.dns available to scripts backed by client.
func RegisterLua(L *lua.LState, client featureDNS.Client) {
	var servers []luaDNSServer
	switch client := client.(type) {
	case *DNS:
		servers = luaServers(client)
	case *localdns.Client:
		servers = []luaDNSServer{{
			id:   "localhost",
			name: "localhost",
			query: func(_ context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
				return client.LookupIP(domain, option)
			},
		}}
	}
	registerLua(L, servers, client)
}

// RegisterLua makes xray.dns available to DNS scripts.
func (s *DNS) RegisterLua(L *lua.LState) {
	registerLua(L, luaServers(s), nil)
}

func luaServers(s *DNS) []luaDNSServer {
	servers := make([]luaDNSServer, len(s.clients))
	for i, client := range s.clients {
		servers[i] = luaDNSServer{id: client.id, name: client.Name(), query: client.QueryIP}
	}
	return servers
}

func registerLua(L *lua.LState, servers []luaDNSServer, client featureDNS.Client) {
	L.PreloadModule("xray.dns", func(L *lua.LState) int {
		serverList := L.NewTable()
		for i, client := range servers {
			server := L.NewTable()

			server.RawSetString("ID", lua.LString(client.id))

			server.RawSetString("Query", L.NewFunction(func(L *lua.LState) int {
				domain, ok := L.Get(2).(lua.LString)
				if !ok {
					L.RaiseError("server:Query requires a domain")
					return 0
				}
				option := featureDNS.IPOption{
					IPv4Enable: L.CheckBool(3),
					IPv6Enable: L.CheckBool(4),
					FakeEnable: L.CheckBool(5),
				}
				ctx := L.Context()
				if ctx == nil {
					L.RaiseError("server:Query requires an active DNS query")
					return 0
				}
				var ips []net.IP
				var ttl uint32
				var err error
				if !option.FakeEnable && strings.EqualFold(client.name, "FakeDNS") {
					err = featureDNS.ErrEmptyResponse
				} else {
					ips, ttl, err = client.query(ctx, string(domain), option)
				}
				addresses := L.NewUserData()
				addresses.Value = ips
				L.Push(addresses)
				L.Push(lua.LNumber(ttl))
				if err != nil {
					ud := L.NewUserData()
					ud.Value = err
					L.Push(ud)
				} else {
					L.Push(lua.LNil)
				}
				return 3
			}))
			serverList.RawSetInt(i+1, server)
		}

		module := L.NewTable()
		if servers != nil {
			module.RawSetString("Servers", serverList)
		}
		if client != nil {
			module.RawSetString("Query", newLuaClientQuery(L, client))
		}
		L.Push(module)
		return 1
	})
}

func newLuaClientQuery(L *lua.LState, client featureDNS.Client) *lua.LFunction {
	return L.NewFunction(func(L *lua.LState) int {
		domain, ok := L.Get(1).(lua.LString)
		if !ok {
			L.RaiseError("dns.Query requires a domain")
			return 0
		}
		option := featureDNS.IPOption{
			IPv4Enable: L.CheckBool(2),
			IPv6Enable: L.CheckBool(3),
			FakeEnable: L.CheckBool(4),
		}
		if L.Context() == nil {
			L.RaiseError("dns.Query requires an active DNS query")
			return 0
		}
		ips, ttl, err := client.LookupIP(string(domain), option)
		addresses := L.NewUserData()
		addresses.Value = ips
		L.Push(addresses)
		L.Push(lua.LNumber(ttl))
		if err != nil {
			ud := L.NewUserData()
			ud.Value = err
			L.Push(ud)
		} else {
			L.Push(lua.LNil)
		}
		return 3
	})
}

// callLuaHook invokes HandleDNSQuery in the supplied state.
// Returned slices and IP bytes may share storage with DNS caches or matcher inputs.
func (s *DNS) callLuaHook(L *lua.LState, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	top := L.GetTop()
	defer L.SetTop(top)
	fn := L.GetGlobal("HandleDNSQuery")
	if fn.Type() != lua.LTFunction {
		return nil, 0, errors.New("DNS script must define HandleDNSQuery(...)")
	}
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true},
		lua.LString(strings.ToLower(domain)), lua.LBool(option.IPv4Enable),
		lua.LBool(option.IPv6Enable), lua.LBool(option.FakeEnable)); err != nil {
		return nil, 0, err
	}
	return readLuaDNSResult(L.Get(-3), L.Get(-2), L.Get(-1))
}

func readLuaDNSResult(addresses, ttlValue, errorValue lua.LValue) ([]net.IP, uint32, error) {
	if errorValue != lua.LNil {
		if ud, ok := errorValue.(*lua.LUserData); ok {
			if err, ok := ud.Value.(error); ok {
				return nil, 0, err
			}
		}
		if s, ok := errorValue.(lua.LString); ok {
			return nil, 0, errors.New(string(s))
		}
		return nil, 0, errors.New("DNS script error must be an error or string")
	}
	ttl, ok := ttlValue.(lua.LNumber)
	if !ok || ttl < 0 || ttl > math.MaxUint32 || math.Trunc(float64(ttl)) != float64(ttl) {
		return nil, 0, errors.New("DNS script returned invalid TTL")
	}
	if addresses == lua.LNil {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	ud, ok := addresses.(*lua.LUserData)
	if !ok {
		return nil, 0, errors.New("DNS script IPs must be native IP slice userdata")
	}
	ips, ok := ud.Value.([]net.IP)
	if !ok {
		return nil, 0, errors.New("DNS script IPs must be native IP slice userdata")
	}
	if len(ips) == 0 {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	return ips, uint32(ttl), nil
}
