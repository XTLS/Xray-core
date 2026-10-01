package router

import (
	"context"
	"time"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	luamgr "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/features/routing"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 10 * time.Second

type scriptEngine struct {
	router *Router
	pool   *luamgr.Pool
}

func newScriptEngine(path string, router *Router) (*scriptEngine, error) {
	program, err := luamgr.CompileFile(path)
	if err != nil {
		return nil, err
	}
	e := &scriptEngine{router: router}
	e.pool, err = luamgr.NewPool(router.ctx, func(poolCtx context.Context) (*lua.LState, error) {
		initCtx, cancel := context.WithTimeout(poolCtx, scriptExecutionTimeout)
		defer cancel()
		L, err := program.NewState(initCtx, func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			router.RegisterLua(L)
			dns.RegisterLua(L, router.dns)
		})
		if err != nil {
			return nil, err
		}
		if L.GetGlobal("HandleRoute").Type() != lua.LTFunction {
			L.Close()
			return nil, errors.New("routing script must define HandleRoute(...)")
		}
		return L, nil
	})
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
	L, err := e.pool.Acquire()
	if err != nil {
		return nil, err
	}
	reusable := false
	defer func() {
		e.pool.Release(L, reusable)
	}()
	callCtx, cancel := context.WithTimeout(e.pool.Context(), scriptExecutionTimeout)
	defer cancel()
	tag, ruleTag, err := e.router.CallLuaHook(L, callCtx, ctx)
	if err != nil {
		return nil, err
	}
	reusable = true
	if tag == "" {
		return nil, common.ErrNoClue
	}
	return &Route{Context: ctx, outboundTag: tag, ruleTag: ruleTag}, nil
}
