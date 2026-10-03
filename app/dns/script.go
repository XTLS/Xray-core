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
	e.pool, err = luamgr.NewPool(server.ctx, program.NewStateFactory(
		scriptExecutionTimeout,
		func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			server.RegisterLua(L)
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleDNSQuery").Type() != lua.LTFunction {
				return errors.New("DNS script must define HandleDNSQuery(...)")
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}
	errors.LogInfo(server.ctx, "DNS script initialized from ", path)
	return e, nil
}

func (e *scriptEngine) close() {
	e.pool.Close()
}

func (e *scriptEngine) query(domain string, option dns.IPOption) (ips []net.IP, ttl uint32, err error) {
	err = e.pool.WithState(func(L *lua.LState) error {
		luaCtx, cancel := context.WithTimeout(e.pool.Context(), scriptExecutionTimeout)
		defer cancel()
		var luaErr error
		ips, ttl, luaErr = e.dns.CallLuaHook(L, luaCtx, domain, option)
		return luaErr
	})
	return
}
