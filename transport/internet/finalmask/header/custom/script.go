package custom

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	lua "github.com/yuin/gopher-lua"
)

const (
	scriptPacketTimeout    = time.Second
	scriptHandshakeTimeout = 30 * time.Second
	scriptInitTimeout      = 120 * time.Second
	scriptRegistrySize     = 256
)

const (
	headerHook = "HandleHeader"
	writeHook  = "HandleHeaderWrite"
	readHook   = "HandleHeaderRead"
)

const (
	roleClient = "client"
	roleServer = "server"
)

type scriptEngine struct {
	pool *xlua.Pool
}

// TODO: close the pool of a mask whose inbound or outbound the API removed.
var (
	scriptsMu sync.Mutex
	scripts   = make(map[any]*scriptEngine)
)

func scriptEngineFor(key any, script string) (*scriptEngine, error) {
	scriptsMu.Lock()
	defer scriptsMu.Unlock()

	if engine := scripts[key]; engine != nil {
		return engine, nil
	}

	engine, err := newScriptEngine(script)
	if err != nil {
		return nil, err
	}
	scripts[key] = engine
	return engine, nil
}

func newScriptEngine(script string) (*scriptEngine, error) {
	program, err := xlua.Compile(script)
	if err != nil {
		return nil, err
	}

	pool, err := xlua.NewPool(context.Background(), scriptHandshakeTimeout, program.NewStateFactory(
		scriptInitTimeout,
		scriptRegistrySize,
		func(L *lua.LState) {
			log.RegisterLua(L)
			RegisterLua(L)
			registerStream(L)
			registerPacketHooks(L)
		},
		validate))
	if err != nil {
		return nil, err
	}

	return &scriptEngine{pool: pool}, nil
}

func (e *scriptEngine) handshake(role string, conn net.Conn) error {
	var reported error
	if err := e.pool.WithState(nil, 0, func(L *lua.LState) error {
		var err error
		reported, err = callHeaderHook(L, role, conn)
		return err
	}); err != nil {
		return err
	}
	return reported
}

func callHeaderHook(L *lua.LState, role string, conn net.Conn) (reported error, err error) {
	data, stream, err := luaStream(L)
	if err != nil {
		return nil, err
	}
	fn := L.GetGlobal(headerHook)
	if fn.Type() != lua.LTFunction {
		return nil, errors.New("header script must define ", headerHook, "(...)")
	}

	*stream = headerStream{conn: conn, open: true}
	defer func() { *stream = headerStream{} }()

	address := ""
	if addr := conn.RemoteAddr(); addr != nil {
		address = addr.String()
	}
	if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, data, lua.LString(address), lua.LString(role)); err != nil {
		return nil, err
	}
	return xlua.ReadError(L.Get(-1), "header script error must be an error or a string"), nil
}

func headerScript(key any, script string) (*scriptEngine, error) {
	if script == "" {
		return nil, nil
	}
	engine, err := scriptEngineFor(key, script)
	if err != nil {
		return nil, errors.New("failed to initialize the header script ", script).Base(err)
	}
	return engine, nil
}

func runHeaderScript(engine *scriptEngine, role string, conn net.Conn) bool {
	if err := engine.handshake(role, conn); err != nil {
		errors.LogWarningInner(context.Background(), err, "the header script refused the connection")
		return false
	}
	return true
}

func (e *scriptEngine) header(role, address string, into []byte) ([]byte, error) {
	var header []byte
	if err := e.pool.WithState(nil, scriptPacketTimeout, func(L *lua.LState) error {
		data, builder, err := luaBuilder(L)
		if err != nil {
			return err
		}
		fn := L.GetGlobal(writeHook)
		if fn.Type() != lua.LTFunction {
			return errors.New("header script must define ", writeHook, "(...)")
		}

		builder.bytes, builder.open = into[:0], true
		defer func() { builder.bytes, builder.open = nil, false }()

		if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, data, lua.LString(address), lua.LString(role)); err != nil {
			return err
		}
		if reported := xlua.ReadError(L.Get(-1), "header script error must be an error or a string"); reported != nil {
			return reported
		}
		header = builder.bytes
		return nil
	}); err != nil {
		return nil, err
	}
	return header, nil
}

func (e *scriptEngine) strip(role, address string, packet []byte) (int, error) {
	strip := 0
	if err := e.pool.WithState(nil, scriptPacketTimeout, func(L *lua.LState) error {
		data, view, err := luaPacket(L)
		if err != nil {
			return err
		}
		fn := L.GetGlobal(readHook)
		if fn.Type() != lua.LTFunction {
			return errors.New("header script must define ", readHook, "(...)")
		}

		view.data, view.open = packet, true
		defer func() { view.data, view.open = nil, false }()

		if err := L.CallByParam(lua.P{Fn: fn, NRet: 1, Protect: true}, data, lua.LString(address), lua.LString(role)); err != nil {
			return err
		}
		size, ok := L.Get(-1).(lua.LNumber)
		if !ok {
			return errors.New("the packet does not carry a header the script knows")
		}
		if !(size >= 0 && int(size) <= len(packet)) {
			return errors.New("the script strips ", int64(size), " bytes of a ", len(packet), " byte packet")
		}
		strip = int(size)
		return nil
	}); err != nil {
		return 0, err
	}
	return strip, nil
}

func validate(L *lua.LState) error {
	for _, hook := range []string{headerHook, writeHook, readHook} {
		if L.GetGlobal(hook).Type() == lua.LTFunction {
			return nil
		}
	}
	return errors.New("header script must define ", headerHook, "(...), or ", writeHook, "(...) and ", readHook, "(...)")
}
