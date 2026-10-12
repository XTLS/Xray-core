package dns

import (
	"context"
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
	pool *xlua.Pool
	ctx context.Context
	cancel context.CancelFunc
}

func newScriptEngine(path string, server *DNS) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(server.ctx)
	pool, err := xlua.NewPool(ctx, scriptExecutionTimeout, program.NewStateFactory(
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
		cancel()
		return nil, err
	}

	errors.LogInfo(server.ctx, "DNS script initialized from ", path)
	return &scriptEngine{pool: pool, ctx: ctx, cancel: cancel}, nil
}

func (e *scriptEngine) close() {
	e.cancel()
	e.pool.Close()
}

func (e *scriptEngine) query(domain string, option dns.IPOption) (ips []net.IP, ttl uint32, queryErr error) {
	return e.queryContext(nil, domain, option)
}

func (e *scriptEngine) queryContext(ctx context.Context, domain string, option dns.IPOption) (ips []net.IP, ttl uint32, queryErr error) {
	if ctx == nil { ctx = e.ctx }
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := ctx.Err(); err != nil { return nil, 0, err }
	err := e.pool.WithState(ctx, 0, func(L *lua.LState) error {
		if err := callLuaQuery(L, domain, option); err != nil {
			return err
		}
		ips, ttl, queryErr = readLuaQueryResult(L)
		return nil
	})
	if contextErr := ctx.Err(); contextErr != nil { return nil, 0, contextErr }
	if err != nil {
		return nil, 0, err
	}
	return ips, ttl, queryErr
}
