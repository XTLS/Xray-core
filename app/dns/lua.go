package dns

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
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

// registerLua makes xray.dns available to DNS scripts.
func (s *DNS) registerLua(L *lua.LState) {
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
		pushIPs := xlua.NewSlicePusher[net.IP](L)

		serverList := L.CreateTable(len(servers), 0)
		for i, client := range servers {
			server := L.CreateTable(0, 2)

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
				pushIPs(L, ips)
				xlua.PushNumber(L, ttl)
				xlua.PushError(L, err)
				return 3
			}))
			serverList.RawSetInt(i+1, server)
		}

		module := L.CreateTable(0, 2)
		if servers != nil {
			module.RawSetString("Servers", serverList)
		}
		if client != nil {
			module.RawSetString("Query", newLuaClientQuery(L, client, pushIPs))
		}
		L.Push(module)
		return 1
	})
}

func newLuaClientQuery(L *lua.LState, client featureDNS.Client, pushIPs func(*lua.LState, []net.IP)) *lua.LFunction {
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
		pushIPs(L, ips)
		xlua.PushNumber(L, ttl)
		xlua.PushError(L, err)
		return 3
	})
}

// callLuaQuery runs HandleDNSQuery and leaves (ips, ttl, err) on the stack.
func callLuaQuery(L *lua.LState, domain string, option featureDNS.IPOption) error {
	fn := L.GetGlobal("HandleDNSQuery")
	if fn.Type() != lua.LTFunction {
		return errors.New("DNS script must define HandleDNSQuery(...)")
	}

	return L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true},
		lua.LString(strings.ToLower(domain)),
		lua.LBool(option.IPv4Enable),
		lua.LBool(option.IPv6Enable),
		lua.LBool(option.FakeEnable))
}

// readLuaQueryResult reads (ips, ttl, err) from the stack without copying the IPs.
func readLuaQueryResult(L *lua.LState) ([]net.IP, uint32, error) {
	if err := xlua.ReadError(L.Get(-1), "DNS script error must be an error or string"); err != nil {
		return nil, 0, err
	}

	ttl, err := xlua.ReadUint32(L.Get(-2), "DNS script returned invalid TTL")
	if err != nil {
		return nil, 0, err
	}

	addresses := L.Get(-3)
	if addresses == lua.LNil {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	ips, err := xlua.ReadUserData[[]net.IP](addresses, "DNS script IPs must be native IP slice userdata")
	if err != nil {
		return nil, 0, err
	}
	if len(ips) == 0 {
		return nil, 0, featureDNS.ErrEmptyResponse
	}

	return ips, ttl, nil
}
