package noise

import (
	"context"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

const (
	scriptExecutionTimeout = time.Second
	scriptInitTimeout      = 120 * time.Second
)

type scriptEngine struct {
	pool *xlua.Pool
}

type scriptPacket struct {
	packet []byte
	delay  time.Duration
}

// TODO: close the pool of a mask whose inbound or outbound the API removed.
var (
	scriptsMu sync.Mutex
	scripts   = make(map[*Config]*scriptEngine)
)

func (c *Config) engine() (*scriptEngine, error) {
	scriptsMu.Lock()
	defer scriptsMu.Unlock()

	if engine := scripts[c]; engine != nil {
		return engine, nil
	}

	engine, err := newScriptEngine(c.Script)
	if err != nil {
		return nil, err
	}
	scripts[c] = engine
	return engine, nil
}

func newScriptEngine(script string) (*scriptEngine, error) {
	program, err := xlua.Compile(script)
	if err != nil {
		return nil, err
	}

	pool, err := xlua.NewPool(context.Background(), scriptExecutionTimeout, program.NewStateFactory(
		scriptInitTimeout,
		256,
		func(L *lua.LState) {
			log.RegisterLua(L)
			RegisterLua(L)
			registerPlan(L)
		},
		func(L *lua.LState) error {
			if L.GetGlobal("HandleNoise").Type() != lua.LTFunction {
				return errors.New("noise script must define HandleNoise(...)")
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	return &scriptEngine{pool: pool}, nil
}

func (e *scriptEngine) packets(addr string, into []scriptPacket) ([]scriptPacket, error) {
	var noise []scriptPacket
	var reported error
	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		var err error
		noise, reported, err = callHook(L, addr, into)
		return err
	}); err != nil {
		return nil, err
	}
	return noise, reported
}

func callHook(L *lua.LState, addr string, into []scriptPacket) (packets []scriptPacket, reported error, err error) {
	data, plan, err := luaPlan(L)
	if err != nil {
		return nil, nil, err
	}
	hook := L.GetGlobal("HandleNoise")
	if hook.Type() != lua.LTFunction {
		return nil, nil, errors.New("noise script must define HandleNoise(...)")
	}

	plan.packets, plan.bytes, plan.open = into[:0], 0, true
	defer func() { plan.packets, plan.open = nil, false }()

	if err := L.CallByParam(lua.P{Fn: hook, NRet: 1, Protect: true}, data, lua.LString(addr)); err != nil {
		return nil, nil, err
	}
	return plan.packets, xlua.ReadError(L.Get(-1), "noise script error must be an error or a string"), nil
}
