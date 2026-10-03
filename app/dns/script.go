package dns

import (
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 6 * time.Second

type scriptEngine struct {
	dns  *DNS
	pool *xlua.Pool
}

func newScriptEngine(path string, server *DNS) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}
	e := &scriptEngine{dns: server}
	e.pool, err = xlua.NewPool(server.ctx, scriptExecutionTimeout, program.NewStateFactory(
		scriptExecutionTimeout*20,
		func(L *lua.LState) {
			geodata.RegisterLua(L)
			log.RegisterLua(L)
			server.registerLua(L)
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
	err = e.pool.WithState(nil, 0, func(L *lua.LState) error {
		var hookErr error
		ips, ttl, hookErr = e.dns.callLuaHook(L, domain, option)
		return hookErr
	})
	return
}
