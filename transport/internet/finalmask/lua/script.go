package lua

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	glua "github.com/yuin/gopher-lua"
)

const (
	packetTimeout    = time.Second
	handshakeTimeout = 30 * time.Second
	initTimeout      = 120 * time.Second
	registrySize     = 256
)

const (
	noiseHook  = "HandleNoise"
	headerHook = "HandleHeader"
	writeHook  = "HandleHeaderWrite"
	readHook   = "HandleHeaderRead"
)

const (
	roleClient = "client"
	roleServer = "server"
)

type scriptPacket struct {
	packet []byte
	delay  time.Duration
}

type engine struct {
	pool  *xlua.Pool
	hooks map[string]bool
}

// TODO: close the pool of a mask whose inbound or outbound the API removed.
var (
	enginesMu sync.Mutex
	engines   = make(map[*Config]*engine)
)

func (c *Config) engine() (*engine, error) {
	enginesMu.Lock()
	defer enginesMu.Unlock()

	if engine := engines[c]; engine != nil {
		return engine, nil
	}

	engine, err := newEngine(c.Script)
	if err != nil {
		return nil, err
	}
	engines[c] = engine
	return engine, nil
}

func newEngine(script string) (*engine, error) {
	program, err := xlua.Compile(script)
	if err != nil {
		return nil, err
	}

	pool, err := xlua.NewPool(context.Background(), packetTimeout, program.NewStateFactory(
		initTimeout,
		registrySize,
		func(L *glua.LState) {
			log.RegisterLua(L)
			RegisterLua(L)
			registerObjects(L)
		},
		nil))
	if err != nil {
		return nil, err
	}

	e := &engine{pool: pool, hooks: make(map[string]bool, 4)}
	if err := pool.WithState(nil, 0, func(L *glua.LState) error {
		for _, hook := range []string{noiseHook, headerHook, writeHook, readHook} {
			e.hooks[hook] = L.GetGlobal(hook).Type() == glua.LTFunction
		}
		return nil
	}); err != nil {
		pool.Close()
		return nil, err
	}
	if !e.hooks[noiseHook] && !e.hooks[headerHook] && !e.hooks[writeHook] && !e.hooks[readHook] {
		pool.Close()
		return nil, errors.New("the script must define ", noiseHook, ", ", headerHook, ", ", writeHook, " or ", readHook)
	}
	return e, nil
}

func (e *engine) packets(role, address string, into []scriptPacket) ([]scriptPacket, error) {
	var noise []scriptPacket
	var reported error
	if err := e.pool.WithState(nil, packetTimeout, func(L *glua.LState) error {
		data, plan, err := object[*noisePlan](L, planKey)
		if err != nil {
			return err
		}
		plan.packets, plan.bytes, plan.open = into[:0], 0, true
		defer func() { plan.packets, plan.open = nil, false }()

		if reported, err = call(L, noiseHook, data, address, role); err != nil {
			return err
		}
		noise = plan.packets
		return nil
	}); err != nil {
		return nil, err
	}
	return noise, reported
}

func (e *engine) handshake(role string, conn net.Conn) error {
	var reported error
	if err := e.pool.WithState(nil, handshakeTimeout, func(L *glua.LState) error {
		data, stream, err := object[*headerStream](L, streamKey)
		if err != nil {
			return err
		}
		*stream = headerStream{conn: conn, open: true}
		defer func() { *stream = headerStream{} }()

		reported, err = call(L, headerHook, data, address(conn.RemoteAddr()), role)
		return err
	}); err != nil {
		return err
	}
	return reported
}

func (e *engine) header(role, address string, into []byte) ([]byte, error) {
	var header []byte
	if err := e.pool.WithState(nil, packetTimeout, func(L *glua.LState) error {
		data, builder, err := object[*headerBuilder](L, headerKey)
		if err != nil {
			return err
		}
		builder.bytes, builder.open = into[:0], true
		defer func() { builder.bytes, builder.open = nil, false }()

		reported, err := call(L, writeHook, data, address, role)
		if err != nil {
			return err
		}
		if reported != nil {
			return reported
		}
		header = builder.bytes
		return nil
	}); err != nil {
		return nil, err
	}
	return header, nil
}

func (e *engine) strip(role, address string, packet []byte) (int, error) {
	strip := 0
	if err := e.pool.WithState(nil, packetTimeout, func(L *glua.LState) error {
		data, view, err := object[*headerPacket](L, packetKey)
		if err != nil {
			return err
		}
		view.data, view.open = packet, true
		defer func() { view.data, view.open = nil, false }()

		fn := L.GetGlobal(readHook)
		if fn.Type() != glua.LTFunction {
			return errors.New("the script must define ", readHook)
		}
		if err := L.CallByParam(glua.P{Fn: fn, NRet: 1, Protect: true}, data, glua.LString(address), glua.LString(role)); err != nil {
			return err
		}
		size, ok := L.Get(-1).(glua.LNumber)
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

func call(L *glua.LState, hook string, data *glua.LUserData, address, role string) (reported error, err error) {
	fn := L.GetGlobal(hook)
	if fn.Type() != glua.LTFunction {
		return nil, errors.New("the script must define ", hook)
	}
	if err := L.CallByParam(glua.P{Fn: fn, NRet: 1, Protect: true}, data, glua.LString(address), glua.LString(role)); err != nil {
		return nil, err
	}
	return xlua.ReadError(L.Get(-1), "the script's error must be an error or a string"), nil
}

func address(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
