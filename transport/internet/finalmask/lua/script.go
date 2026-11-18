package lua

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
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

type hook struct {
	bit  uint32
	name string
}

var (
	noiseHook  = hook{1 << 0, "HandleNoise"}
	headerHook = hook{1 << 1, "HandleHeader"}
	writeHook  = hook{1 << 2, "HandleHeaderWrite"}
	readHook   = hook{1 << 3, "HandleHeaderRead"}

	packetHooks = noiseHook.bit | writeHook.bit | readHook.bit
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
	hooks atomic.Uint32
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
		},
		func(L *glua.LState) error {
			if defined(L) == 0 {
				return errors.New("the script must define at least one hook")
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	e := &engine{pool: pool}
	if err := pool.WithState(nil, 0, func(L *glua.LState) error {
		e.hooks.Store(defined(L))
		return nil
	}); err != nil {
		pool.Close()
		return nil, err
	}
	return e, nil
}

// defined reports the hooks a state defines. A script may drop a hook of its
// own while it runs, and the engine then short circuits that hook for every
// state, but it can never add one back: the masks of a connection are chosen
// when it is made.
func defined(L *glua.LState) uint32 {
	bits := uint32(0)
	for _, h := range []hook{noiseHook, headerHook, writeHook, readHook} {
		if L.GetGlobal(h.name).Type() == glua.LTFunction {
			bits |= h.bit
		}
	}
	return bits
}

func (e *engine) has(h hook) bool {
	return e.hooks.Load()&h.bit != 0
}

func (e *engine) hasAny(bits uint32) bool {
	return e.hooks.Load()&bits != 0
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

		ran, report, err := e.call(L, noiseHook, data, address, role)
		if err != nil {
			return err
		}
		if !ran {
			return nil
		}
		reported = report
		noise = plan.packets
		return nil
	}); err != nil {
		return nil, err
	}
	return noise, reported
}

func (e *engine) handshake(role string, conn net.Conn, timeout time.Duration) error {
	var reported error
	if err := e.pool.WithState(nil, timeout, func(L *glua.LState) error {
		data, stream, err := object[*headerStream](L, streamKey)
		if err != nil {
			return err
		}
		*stream = headerStream{conn: conn, open: true}
		defer func() { *stream = headerStream{} }()

		_, reported, err = e.call(L, headerHook, data, address(conn.RemoteAddr()), role)
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

		ran, reported, err := e.call(L, writeHook, data, address, role)
		if err != nil {
			return err
		}
		if reported != nil {
			return reported
		}
		if !ran {
			return nil
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

		fn := L.GetGlobal(readHook.name)
		if fn.Type() != glua.LTFunction {
			e.unload(readHook)
			return nil
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

func (e *engine) unload(h hook) {
	e.hooks.And(^h.bit)
}

func (e *engine) call(L *glua.LState, h hook, data *glua.LUserData, address, role string) (ran bool, reported error, err error) {
	fn := L.GetGlobal(h.name)
	if fn.Type() != glua.LTFunction {
		e.unload(h)
		return false, nil, nil
	}
	if err := L.CallByParam(glua.P{Fn: fn, NRet: 1, Protect: true}, data, glua.LString(address), glua.LString(role)); err != nil {
		return false, nil, err
	}
	return true, xlua.ReadError(L.Get(-1), "the script's error must be an error or a string"), nil
}

func address(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
