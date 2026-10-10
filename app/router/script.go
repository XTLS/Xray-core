package router

import (
	"time"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/features/routing"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 6 * time.Second

type scriptEngine struct {
	pool *xlua.Pool
}

func newScriptEngine(path string, router *Router) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}

	pool, err := xlua.NewPool(router.ctx, scriptExecutionTimeout, program.NewStateFactory(
		scriptExecutionTimeout*20,
		func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			router.RegisterLua(L)
			dns.RegisterLua(L, router.dns)
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleRoute").Type() != lua.LTFunction {
				return errors.New("routing script must define HandleRoute(...)")
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	errors.LogInfo(router.ctx, "routing script initialized from ", path)
	return &scriptEngine{pool: pool}, nil
}

func (e *scriptEngine) close() {
	e.pool.Close()
}

func (e *scriptEngine) pickRoute(ctx routing.Context) (routing.Route, error) {
	var outboundTag, ruleTag string
	var routeErr error

	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		if err := callLuaRoute(L, ctx); err != nil {
			return err
		}
		outboundTag, ruleTag, routeErr = readLuaRouteResult(L)
		return nil
	}); err != nil {
		return nil, err
	}

	if routeErr != nil {
		return nil, routeErr
	}
	if outboundTag == "" {
		return nil, common.ErrNoClue
	}

	return &Route{Context: ctx, outboundTag: outboundTag, ruleTag: ruleTag}, nil
}
