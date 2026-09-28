package dns

import (
	"context"
	"math"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	featureDNS "github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

// RegisterLua makes xray.dns available to require in an LState.
func (s *DNS) RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.dns", func(L *lua.LState) int {
		servers := L.NewTable()
		for i, client := range s.clients {
			server := L.NewTable()

			server.RawSetString("id", lua.LString(client.id))

			server.RawSetString("query", L.NewFunction(func(L *lua.LState) int {
				domain, ok := L.Get(2).(lua.LString)
				if !ok {
					L.RaiseError("server:query requires a domain")
					return 0
				}
				option := featureDNS.IPOption{
					IPv4Enable: L.CheckBool(3),
					IPv6Enable: L.CheckBool(4),
					FakeEnable: L.CheckBool(5),
				}
				ctx := L.Context()
				if ctx == nil {
					L.RaiseError("server:query requires an active DNS query")
					return 0
				}
				var ips []net.IP
				var ttl uint32
				var err error
				if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
					err = featureDNS.ErrEmptyResponse
				} else {
					ips, ttl, err = client.QueryIP(ctx, string(domain), option)
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
			servers.RawSetInt(i+1, server)
		}
		module := L.NewTable()
		module.RawSetString("servers", servers)
		L.Push(module)
		return 1
	})
}

// CallLuaHook invokes handleDNSQuery in the supplied state.
// Returned slices and IP bytes may share storage with DNS caches or matcher inputs.
func (s *DNS) CallLuaHook(L *lua.LState, ctx context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	previous := L.Context()
	L.SetContext(ctx)
	defer func() {
		if previous == nil {
			L.RemoveContext()
		} else {
			L.SetContext(previous)
		}
	}()
	fn := L.GetGlobal("handleDNSQuery")
	if fn.Type() != lua.LTFunction {
		return nil, 0, errors.New("DNS script must define handleDNSQuery(domain, ipv4, ipv6, fake)")
	}
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true},
		lua.LString(strings.ToLower(domain)), lua.LBool(option.IPv4Enable),
		lua.LBool(option.IPv6Enable), lua.LBool(option.FakeEnable)); err != nil {
		return nil, 0, err
	}
	addresses, ttlValue, errorValue := L.Get(-3), L.Get(-2), L.Get(-1)
	L.Pop(3)
	ips, ttl, err := readLuaDNSResult(addresses, ttlValue, errorValue)
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	return ips, ttl, err
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
