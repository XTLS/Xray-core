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

// RegisterLua makes xray.dns available to require in an LState. The caller
// owns the state and registers modules before running the script top level.
func (s *DNS) RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.dns", func(L *lua.LState) int {
		servers := L.NewTable()
		for i, client := range s.clients {
			server := L.NewTable()

			server.RawSetString("id", lua.LString(client.id))

			server.RawSetString("query", L.NewFunction(func(L *lua.LState) int {
				q := L.CheckTable(2)
				domain, ok := q.RawGetString("domain").(lua.LString)
				if !ok {
					L.RaiseError("server:query requires a domain")
					return 0
				}
				option := featureDNS.IPOption{
					IPv4Enable: q.RawGetString("ipv4") == lua.LTrue,
					IPv6Enable: q.RawGetString("ipv6") == lua.LTrue,
					FakeEnable: q.RawGetString("fake") == lua.LTrue,
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
				result := L.NewTable()
				addresses := L.NewTable()
				for j, ip := range ips {
					address := L.NewUserData()
					address.Value = ip
					addresses.RawSetInt(j+1, address)
				}
				result.RawSetString("ips", addresses)
				result.RawSetString("ttl", lua.LNumber(ttl))
				if err != nil {
					ud := L.NewUserData()
					ud.Value = err
					result.RawSetString("error", ud)
				}
				L.Push(result)
				return 1
			}))
			servers.RawSetInt(i+1, server)
		}
		module := L.NewTable()
		module.RawSetString("servers", servers)
		L.Push(module)
		return 1
	})
}

// CallLuaHook invokes handleDNSQuery on a state owned by the caller. Domain and option
// must already have passed DNS normalization, hosts, and address-family handling.
// The caller serializes access to its state; ctx cancels Lua execution and upstream calls.
func (s *DNS) CallLuaHook(L *lua.LState, ctx context.Context, domain string, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	q := L.NewTable()
	q.RawSetString("domain", lua.LString(strings.ToLower(domain)))
	q.RawSetString("ipv4", lua.LBool(option.IPv4Enable))
	q.RawSetString("ipv6", lua.LBool(option.IPv6Enable))
	q.RawSetString("fake", lua.LBool(option.FakeEnable))
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
		return nil, 0, errors.New("DNS script must define handleDNSQuery(q)")
	}
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, q); err != nil {
		return nil, 0, err
	}
	value := L.Get(-1)
	L.Pop(1)
	ips, ttl, err := decodeLuaDNSResult(value, option)
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	return ips, ttl, err
}

func decodeLuaDNSResult(value lua.LValue, option featureDNS.IPOption) ([]net.IP, uint32, error) {
	table, ok := value.(*lua.LTable)
	if !ok {
		return nil, 0, errors.New("DNS script result must be a table")
	}
	if v := table.RawGetString("error"); v != lua.LNil {
		if ud, ok := v.(*lua.LUserData); ok {
			if err, ok := ud.Value.(error); ok {
				return nil, 0, err
			}
		}
		if s, ok := v.(lua.LString); ok {
			return nil, 0, errors.New(string(s))
		}
		return nil, 0, errors.New("DNS script error must be an error or string")
	}
	ttlValue, ok := table.RawGetString("ttl").(lua.LNumber)
	if !ok || ttlValue < 0 || ttlValue > math.MaxUint32 || math.Trunc(float64(ttlValue)) != float64(ttlValue) {
		return nil, 0, errors.New("DNS script returned invalid TTL")
	}
	var ips []net.IP
	switch addresses := table.RawGetString("ips").(type) {
	case *lua.LTable:
		ips = make([]net.IP, 0, addresses.Len())
		for i := 1; i <= addresses.Len(); i++ {
			ip, err := decodeLuaIP(addresses.RawGetInt(i), i, option)
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, ip)
		}
	case *lua.LUserData:
		addressesIP, ok := addresses.Value.([]net.IP)
		if !ok {
			return nil, 0, errors.New("DNS script result.ips must be an array")
		}
		ips = make([]net.IP, 0, len(addressesIP))
		for i, ip := range addressesIP {
			valid, err := validateLuaIP(ip, i+1, option)
			if err != nil {
				return nil, 0, err
			}
			ips = append(ips, valid)
		}
	default:
		return nil, 0, errors.New("DNS script result.ips must be an array")
	}
	if len(ips) == 0 {
		return nil, 0, featureDNS.ErrEmptyResponse
	}
	return ips, uint32(ttlValue), nil
}

func decodeLuaIP(value lua.LValue, index int, option featureDNS.IPOption) (net.IP, error) {
	address, ok := value.(*lua.LUserData)
	if !ok {
		return nil, errors.New("DNS script returned invalid address at index ", index)
	}
	ip, ok := address.Value.(net.IP)
	if !ok {
		return nil, errors.New("DNS script returned invalid address at index ", index)
	}
	return validateLuaIP(ip, index, option)
}

func validateLuaIP(ip net.IP, index int, option featureDNS.IPOption) (net.IP, error) {
	ip4 := ip.To4()
	if ip.To16() == nil || (ip4 != nil && !option.IPv4Enable) || (ip4 == nil && !option.IPv6Enable) {
		return nil, errors.New("DNS script returned invalid or disabled address at index ", index)
	}
	return append(net.IP(nil), ip...), nil
}
