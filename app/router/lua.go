package router

import (
	"runtime"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	xlua "github.com/xtls/xray-core/common/lua"
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
		module := L.CreateTable(0, 7)

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
				xlua.PushNil(L)
				xlua.PushError(L, errors.New("balancer ", tag, " not found"))
				return 2
			}
			outboundTag, err := balancer.PickOutbound()
			xlua.PushString(L, outboundTag)
			xlua.PushError(L, err)
			return 2
		}))

		module.RawSetString("FindProcess", L.NewFunction(func(L *lua.LState) int {
			pid, name, path, err := findProcess(checkLuaContext(L), net.FindProcess)
			xlua.PushNumber(L, pid)
			xlua.PushString(L, name)
			xlua.PushString(L, path)
			xlua.PushError(L, err)
			return 4
		}))

		L.Push(module)
		return 1
	})
}

func registerLuaContext(L *lua.LState) {
	pushIPs := xlua.NewSlicePusher[net.IP](L)
	attributes := L.NewTypeMetatable(luaAttributesType)
	L.SetField(attributes, "__index", L.NewFunction(func(L *lua.LState) int {
		values := L.CheckUserData(1).Value.(map[string]string)
		key := L.CheckString(2)
		if value, found := values[key]; found {
			xlua.PushString(L, value)
		} else {
			xlua.PushNil(L)
		}
		return 1
	}))
	methods := L.CreateTable(0, 4)
	L.SetFuncs(methods, map[string]lua.LGFunction{
		"GetSourceIPs": func(L *lua.LState) int {
			pushIPs(L, checkLuaContext(L).GetSourceIPs())
			return 1
		},
		"GetTargetIPs": func(L *lua.LState) int {
			pushIPs(L, checkLuaContext(L).GetTargetIPs())
			return 1
		},
		"GetLocalIPs": func(L *lua.LState) int {
			pushIPs(L, checkLuaContext(L).GetLocalIPs())
			return 1
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

// callLuaRoute runs HandleRoute and leaves (outboundTag, ruleTag, err) on the stack.
func callLuaRoute(L *lua.LState, ctx routing.Context) error {
	fn := L.GetGlobal("HandleRoute")
	if fn.Type() != lua.LTFunction {
		return errors.New("routing script must define HandleRoute(...)")
	}

	value := L.NewUserData()
	value.Value = ctx
	L.SetMetatable(value, L.GetTypeMetatable(luaContextType))

	return L.CallByParam(lua.P{Fn: fn, NRet: 3, Protect: true},
		value,
		lua.LString(ctx.GetInboundTag()),
		lua.LNumber(ctx.GetSourcePort()),
		lua.LNumber(ctx.GetTargetPort()),
		lua.LNumber(ctx.GetLocalPort()),
		lua.LString(strings.ToLower(ctx.GetTargetDomain())),
		lua.LNumber(ctx.GetNetwork()),
		lua.LString(ctx.GetProtocol()),
		lua.LString(ctx.GetUser()),
		lua.LNumber(ctx.GetVlessRoute()),
		lua.LBool(ctx.GetSkipDNSResolve()))
}

// readLuaRouteResult reads (outboundTag, ruleTag, err) from the stack.
func readLuaRouteResult(L *lua.LState) (string, string, error) {
	if err := xlua.ReadError(L.Get(-1), "routing script error must be an error or string"); err != nil {
		return "", "", err
	}

	outboundTag, err := xlua.ReadOptionalString(L.Get(-3), "routing script outboundTag must be a string or nil")
	if err != nil || outboundTag == "" {
		return "", "", err
	}

	ruleTag, err := xlua.ReadOptionalString(L.Get(-2), "routing script ruleTag must be a string")
	if err != nil {
		return "", "", err
	}

	return outboundTag, ruleTag, nil
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
