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
	router *Router
	pool   *xlua.Pool
}

func newScriptEngine(path string, router *Router) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}
	e := &scriptEngine{router: router}
	e.pool, err = xlua.NewPool(router.ctx, scriptExecutionTimeout, program.NewStateFactory(
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
	return e, nil
}

func (e *scriptEngine) close() {
	e.pool.Close()
}

func (e *scriptEngine) pickRoute(ctx routing.Context) (routing.Route, error) {
	var tag, ruleTag string
	err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		var hookErr error
		tag, ruleTag, hookErr = e.router.callLuaHook(L, ctx)
		return hookErr
	})
	if err != nil {
		return nil, err
	}
	if tag == "" {
		return nil, common.ErrNoClue
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: ruleTag}, nil
}
