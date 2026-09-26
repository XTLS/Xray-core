package dns

import (
	"context"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	luamgr "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 10 * time.Second

type scriptEngine struct {
	dns  *DNS
	pool *luamgr.Pool
}

func newScriptEngine(path string, server *DNS) (*scriptEngine, error) {
	program, err := luamgr.CompileFile(path)
	if err != nil {
		return nil, err
	}
	e := &scriptEngine{dns: server}
	e.pool, err = luamgr.NewPool(server.ctx, func(poolCtx context.Context) (*lua.LState, error) {
		initCtx, cancel := context.WithTimeout(poolCtx, scriptExecutionTimeout)
		defer cancel()
		L, err := program.NewState(initCtx, func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			server.RegisterLua(L)
		})
		if err != nil {
			return nil, err
		}
		if L.GetGlobal("handleDNSQuery").Type() != lua.LTFunction {
			L.Close()
			return nil, errors.New("DNS script must define handleDNSQuery(q)")
		}
		return L, nil
	})
	if err != nil {
		return nil, err
	}
	errors.LogInfo(server.ctx, "DNS script initialized from ", path)
	return e, nil
}

func (e *scriptEngine) close() {
	e.pool.Close()
}

func (e *scriptEngine) query(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	L, err := e.pool.Acquire()
	if err != nil {
		return nil, 0, err
	}
	reusable := false
	defer func() {
		e.pool.Release(L, reusable)
	}()
	queryCtx, cancel := context.WithTimeout(e.pool.Context(), scriptExecutionTimeout)
	defer cancel()
	ips, ttl, err := e.dns.CallLuaHook(L, queryCtx, domain, option)
	if err == nil {
		reusable = true
	}
	return ips, ttl, err
}
