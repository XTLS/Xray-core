package lua

import (
	"bytes"
	"context"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	glua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Program holds immutable bytecode that can be run by independent LStates.
type Program struct {
	proto      *glua.FunctionProto
	privileged bool
}

// LStateFactory returns a fully initialized state or nil and an error.
// Implementations must close partial states on failure; callers own successful states.
type LStateFactory func(context.Context) (*glua.LState, error)

// Compile reads a Lua file or decodes an inline script and compiles it into an immutable program.
func Compile(script string) (*Program, error) {
	var code []byte
	var err error
	name := "[inline]"
	privileged := false
	if strings.HasPrefix(script, base64.GzipPrefix) || strings.HasPrefix(script, base64.Prefix) {
		// TODO: Restore inline script support and re-enable the related tests.
		return nil, errors.New("currently unavailable")
		code, err = base64.Decode(script)
	} else if name, err = platform.ResolveLuaFile(script); err == nil {
		if code, err = os.ReadFile(name); err == nil {
			privileged, err = verifyPrivilegedSignature(code)
		}
	}
	if err != nil {
		return nil, err
	}

	chunk, err := parse.Parse(bytes.NewReader(code), name)
	if err != nil {
		return nil, err
	}
	proto, err := glua.Compile(chunk, name)
	if err != nil {
		return nil, err
	}
	return &Program{proto: proto, privileged: privileged}, nil
}

// NewState creates a state, runs register, executes the program under ctx, and
// runs validate. It removes the initialization context before returning a state
// owned by the caller.
func (p *Program) NewState(ctx context.Context, register func(*glua.LState), validate func(*glua.LState) error) (*glua.LState, error) {
	var L *glua.LState
	if p.privileged {
		L = glua.NewState()
	} else {
		L = newSandboxedState()
	}
	valid := false
	defer func() {
		if !valid {
			L.Close()
		}
	}()
	L.SetContext(ctx)
	defer L.RemoveContext()
	if register != nil {
		register(L)
	}
	if !p.privileged {
		// Host registration needs package.preload; scripts must not access the cache or loaders.
		L.SetGlobal(glua.LoadLibName, glua.LNil)
	}
	L.Push(L.NewFunctionFromProto(p.proto))
	// Execute the Lua script's top level.
	if err := L.PCall(0, 0, nil); err != nil {
		return nil, err
	}
	if validate != nil {
		if err := validate(L); err != nil {
			return nil, err
		}
	}
	valid = true
	return L, nil
}

func newSandboxedState() *glua.LState {
	L := glua.NewState(glua.Options{SkipOpenLibs: true})

	for _, lib := range []struct {
		name string
		open glua.LGFunction
	}{
		{glua.LoadLibName, glua.OpenPackage},
		{glua.BaseLibName, glua.OpenBase},
		{glua.TabLibName, glua.OpenTable},
		{glua.StringLibName, glua.OpenString},
		{glua.MathLibName, glua.OpenMath},
	} {
		L.Push(L.NewFunction(lib.open))
		L.Push(glua.LString(lib.name))
		L.Call(1, 0)
	}

	for _, name := range []string{
		"dofile", "loadfile", "load", "loadstring", "getfenv", "setfenv",
		"getmetatable", "setmetatable", "rawget", "rawset",
		"collectgarbage", "module", "newproxy", "print", "_printregs",
	} {
		L.SetGlobal(name, glua.LNil)
	}
	L.GetGlobal(glua.StringLibName).(*glua.LTable).RawSetString("dump", glua.LNil)
	L.GetGlobal(glua.MathLibName).(*glua.LTable).RawSetString("randomseed", glua.LNil)

	// Hide object addresses without invoking __tostring.
	L.SetGlobal("tostring", L.NewFunction(func(L *glua.LState) int {
		value := L.CheckAny(1)
		switch value.Type() {
		case glua.LTNil, glua.LTBool, glua.LTNumber, glua.LTString:
			L.Push(glua.LString(value.String()))
		default:
			L.Push(glua.LString("<opaque>"))
		}
		return 1
	}))

	// Capture preload before package is hidden; require() reads loaders from the registry.
	module := L.GetGlobal(glua.LoadLibName).(*glua.LTable)
	preload := module.RawGetString("preload").(*glua.LTable)
	loaders := L.CreateTable(1, 0)
	loaders.RawSetInt(1, L.NewFunction(func(L *glua.LState) int {
		name := L.CheckString(1)
		loader := preload.RawGetString(name)
		if loader == glua.LNil {
			loader = glua.LString("no preloaded module: " + name)
		}
		L.Push(loader)
		return 1
	}))
	module.RawSetString("loaders", loaders)
	L.SetField(L.Get(glua.RegistryIndex), "_LOADERS", loaders)
	for _, name := range []string{"loadlib", "seeall", "path", "cpath", "config"} {
		module.RawSetString(name, glua.LNil)
	}

	return L
}

// NewStateFactory returns a factory that gives each state an initialization timeout.
func (p *Program) NewStateFactory(initTimeout time.Duration, register func(*glua.LState), validate func(*glua.LState) error) LStateFactory {
	return func(ctx context.Context) (*glua.LState, error) {
		initCtx, cancel := context.WithTimeout(ctx, initTimeout)
		defer cancel()
		return p.NewState(initCtx, register, validate)
	}
}
