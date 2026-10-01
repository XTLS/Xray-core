package router

import (
	"context"
	"runtime"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	lua "github.com/yuin/gopher-lua"
)

const (
	luaContextType    = "xray.router.Context"
	luaAttributesType = "xray.router.Attributes"
)

// RegisterLua makes xray.router available to routing scripts.
func (r *Router) RegisterLua(L *lua.LState) {
	registerLuaContext(L)

	L.PreloadModule("xray.router", func(L *lua.LState) int {
		module := L.NewTable()

		module.RawSetString("NetworkUnknown", lua.LNumber(net.Network_Unknown))
		module.RawSetString("NetworkTCP", lua.LNumber(net.Network_TCP))
		module.RawSetString("NetworkUDP", lua.LNumber(net.Network_UDP))
		module.RawSetString("NetworkUNIX", lua.LNumber(net.Network_UNIX))
		module.RawSetString("LocalOS", lua.LString(runtime.GOOS))

		module.RawSetString("PickOutbound", L.NewFunction(func(L *lua.LState) int {
			tag, ok := L.Get(2).(lua.LString)
			if !ok {
				L.ArgError(2, "balancer tag must be a string")
				return 0
			}
			balancer, found := (*r.balancers.Load())[string(tag)]
			if !found {
				L.Push(lua.LNil)
				pushLuaError(L, errors.New("balancer ", tag, " not found"))
				return 2
			}
			outboundTag, err := balancer.PickOutbound()
			L.Push(lua.LString(outboundTag))
			pushLuaError(L, err)
			return 2
		}))

		module.RawSetString("FindProcess", L.NewFunction(func(L *lua.LState) int {
			pid, name, path, err := findProcess(checkLuaContext(L), net.FindProcess)
			L.Push(lua.LNumber(pid))
			L.Push(lua.LString(name))
			L.Push(lua.LString(path))
			pushLuaError(L, err)
			return 4
		}))

		L.Push(module)
		return 1
	})
}

func registerLuaContext(L *lua.LState) {
	attributes := L.NewTypeMetatable(luaAttributesType)
	L.SetField(attributes, "__index", L.NewFunction(func(L *lua.LState) int {
		values := L.CheckUserData(1).Value.(map[string]string)
		key := L.CheckString(2)
		if value, found := values[key]; found {
			L.Push(lua.LString(value))
		} else {
			L.Push(lua.LNil)
		}
		return 1
	}))
	methods := L.NewTable()
	L.SetFuncs(methods, map[string]lua.LGFunction{
		"GetSourceIPs": func(L *lua.LState) int {
			return pushLuaIPs(L, checkLuaContext(L).GetSourceIPs())
		},
		"GetTargetIPs": func(L *lua.LState) int {
			return pushLuaIPs(L, checkLuaContext(L).GetTargetIPs())
		},
		"GetLocalIPs": func(L *lua.LState) int {
			return pushLuaIPs(L, checkLuaContext(L).GetLocalIPs())
		},
		"GetAttributes": func(L *lua.LState) int {
			values := L.NewUserData()
			values.Value = checkLuaContext(L).GetAttributes()
			L.SetMetatable(values, attributes)
			L.Push(values)
			return 1
		},
	})
	L.SetField(L.NewTypeMetatable(luaContextType), "__index", methods)
}

func checkLuaContext(L *lua.LState) routing.Context {
	ctx, ok := L.CheckUserData(1).Value.(routing.Context)
	if !ok {
		L.ArgError(1, "routing context expected")
	}
	return ctx
}

func pushLuaIPs(L *lua.LState, ips []net.IP) int {
	addresses := L.NewUserData()
	addresses.Value = ips
	L.Push(addresses)
	return 1
}

func pushLuaError(L *lua.LState, err error) {
	if err == nil {
		L.Push(lua.LNil)
		return
	}
	value := L.NewUserData()
	value.Value = err
	L.Push(value)
}

// CallLuaHook invokes HandleRoute in the supplied state.
func (r *Router) CallLuaHook(L *lua.LState, ctx context.Context, routeCtx routing.Context) (string, string, error) {
	previous, top := L.Context(), L.GetTop()
	L.SetContext(ctx)
	defer func() {
		L.SetTop(top)
		if previous == nil {
			L.RemoveContext()
		} else {
			L.SetContext(previous)
		}
	}()
	fn := L.GetGlobal("HandleRoute")
	if fn.Type() != lua.LTFunction {
		return "", "", errors.New("routing script must define HandleRoute(...)")
	}
	value := L.NewUserData()
	value.Value = routeCtx
	L.SetMetatable(value, L.GetTypeMetatable(luaContextType))
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true},
		value, lua.LString(routeCtx.GetInboundTag()), lua.LNumber(routeCtx.GetSourcePort()),
		lua.LNumber(routeCtx.GetTargetPort()), lua.LNumber(routeCtx.GetLocalPort()),
		lua.LString(routeCtx.GetTargetDomain()), lua.LNumber(routeCtx.GetNetwork()),
		lua.LString(routeCtx.GetProtocol()), lua.LString(routeCtx.GetUser()),
		lua.LNumber(routeCtx.GetVlessRoute()), lua.LBool(routeCtx.GetSkipDNSResolve())); err != nil {
		return "", "", err
	}
	return readLuaRouteResult(L.Get(-3), L.Get(-2), L.Get(-1))
}

func readLuaRouteResult(tagValue, ruleValue, errorValue lua.LValue) (string, string, error) {
	if errorValue != lua.LNil {
		if value, ok := errorValue.(*lua.LUserData); ok {
			if err, ok := value.Value.(error); ok {
				return "", "", err
			}
		}
		if value, ok := errorValue.(lua.LString); ok {
			return "", "", errors.New(string(value))
		}
		return "", "", errors.New("routing script error must be an error or string")
	}
	if tagValue == lua.LNil {
		return "", "", nil
	}
	tag, ok := tagValue.(lua.LString)
	if !ok {
		return "", "", errors.New("routing script outboundTag must be a string or nil")
	}
	if tag == "" {
		return "", "", nil
	}
	var ruleTag string
	if ruleValue != lua.LNil {
		value, ok := ruleValue.(lua.LString)
		if !ok {
			return "", "", errors.New("routing script ruleTag must be a string")
		}
		ruleTag = string(value)
	}
	return string(tag), ruleTag, nil
}

type processFinder func(string, string, uint16, string, uint16) (int, string, string, error)

func findProcess(ctx routing.Context, finder processFinder) (int, string, string, error) {
	sources := ctx.GetSourceIPs()
	if len(sources) == 0 {
		return 0, "", "", errors.New("process lookup requires a source IP")
	}
	var network string
	switch ctx.GetNetwork() {
	case net.Network_TCP:
		network = "tcp"
	case net.Network_UDP:
		network = "udp"
	default:
		return 0, "", "", errors.New("process lookup requires TCP or UDP")
	}
	targetIP, targetPort := "", uint16(0)
	if targets := ctx.GetTargetIPs(); len(targets) > 0 {
		targetIP, targetPort = targets[0].String(), uint16(ctx.GetTargetPort())
	}
	return finder(network, sources[0].String(), uint16(ctx.GetSourcePort()), targetIP, targetPort)
}
