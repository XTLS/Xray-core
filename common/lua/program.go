package lua

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform/filesystem"
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
	} else if name, err = filesystem.ResolveLuaFile(script); err == nil {
		code, err = os.ReadFile(name)
		// TODO: Restore privileged signature authorization and re-enable the related tests and CLI entries.
		// if err == nil {
		// 	privileged, err = verifyPrivilegedSignature(code)
		// }
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
// Choose registrySize for the script type's expected stack usage, balancing
// per-state memory usage against the number of states retained in a pool.
func (p *Program) NewState(ctx context.Context, registrySize int, register func(*glua.LState), validate func(*glua.LState) error) (*glua.LState, error) {
	options := glua.Options{
		RegistrySize:     registrySize,
		RegistryMaxSize:  glua.RegistrySize,
		RegistryGrowStep: registrySize,
	}
	var L *glua.LState
	if p.privileged {
		L = glua.NewState(options)
	} else {
		L = newSandboxedState(options)
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
		// Hide package internals to prevent data snooping and sandbox escape.
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

func newSandboxedState(options glua.Options) *glua.LState {
	options.SkipOpenLibs = true
	L := glua.NewState(options)

	for _, lib := range []struct {
		name string
		open glua.LGFunction
	}{
		{glua.LoadLibName, glua.OpenPackage},
		{glua.BaseLibName, glua.OpenBase},
		{glua.TabLibName, glua.OpenTable},
		{glua.StringLibName, glua.OpenString},
		{glua.MathLibName, glua.OpenMath},
		{glua.OsLibName, glua.OpenOs},
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

	// Prevent printing memory addresses that reveal the memory layout.
	toString := func(value glua.LValue) glua.LString {
		result := "<opaque>"
		switch value.Type() {
		case glua.LTNil, glua.LTBool, glua.LTNumber, glua.LTString:
			result = value.String()
		case glua.LTUserData:
			switch native := value.(*glua.LUserData).Value.(type) {
			case error: // Errors can also implement fmt.Stringer; redact them first.
				result = redactMemoryAddresses(native.Error())
			case fmt.Stringer:
				result = native.String()
			}
		}
		return glua.LString(result)
	}
	L.SetGlobal("tostring", L.NewFunction(func(L *glua.LState) int {
		L.Push(toString(L.CheckAny(1)))
		return 1
	}))

	// Prevent printing memory addresses that reveal the memory layout.
	stringLib := L.GetGlobal(glua.StringLibName).(*glua.LTable)
	stringLib.RawSetString("dump", glua.LNil)
	format := stringLib.RawGetString("format")
	stringLib.RawSetString("format", L.NewFunction(func(L *glua.LState) int {
		nargs := L.GetTop()
		for i := 2; i <= nargs; i++ {
			value := L.Get(i)
			switch value.Type() {
			case glua.LTBool, glua.LTNumber, glua.LTString:
				continue
			}
			L.Replace(i, toString(value))
		}
		L.Insert(format, 1)
		L.Call(nargs, 1)
		return 1
	}))

	// Redact addresses before caught errors become readable by the script.
	redactError := func(value glua.LValue) glua.LValue {
		if message, ok := value.(glua.LString); ok {
			if redacted := redactMemoryAddresses(string(message)); redacted != string(message) {
				return glua.LString(redacted)
			}
		}
		return value
	}
	for _, name := range []string{"pcall", "xpcall"} {
		call := L.GetGlobal(name)
		L.SetGlobal(name, L.NewFunction(func(L *glua.LState) int {
			nargs := L.GetTop()
			if name == "xpcall" {
				L.CheckFunction(1)
				handler := L.CheckFunction(2)
				L.Replace(2, L.NewFunction(func(L *glua.LState) int {
					L.Replace(1, redactError(L.Get(1)))
					L.Insert(handler, 1)
					L.Call(1, 1)
					return 1
				}))
			}
			L.Insert(call, 1)
			L.Call(nargs, glua.MultRet)
			if L.Get(1) == glua.LFalse {
				L.Replace(2, redactError(L.Get(2)))
			}
			return L.GetTop()
		}))
	}

	// Prevent seed output from compromising cryptographic security.
	L.GetGlobal(glua.MathLibName).(*glua.LTable).RawSetString("randomseed", glua.LNil)

	// Keep only time functions, including when os is accessed through require.
	osLib := L.GetGlobal(glua.OsLibName).(*glua.LTable)
	for key, _ := osLib.Next(glua.LNil); key != glua.LNil; key, _ = osLib.Next(key) {
		switch key {
		case glua.LString("clock"), glua.LString("date"), glua.LString("difftime"), glua.LString("time"):
		default:
			osLib.RawSet(key, glua.LNil)
		}
	}

	// Prevent module injection through the global package table.
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

var memoryAddressPattern = regexp.MustCompile(`0[xX][0-9a-fA-F]+`)

func redactMemoryAddresses(message string) string {
	if !strings.Contains(message, "0x") && !strings.Contains(message, "0X") {
		return message
	}
	return memoryAddressPattern.ReplaceAllString(message, "<address>")
}

// NewStateFactory returns a factory that gives each state an initialization timeout.
// Choose registrySize for the script type's expected stack usage, balancing
// per-state memory usage against the number of states retained in a pool.
func (p *Program) NewStateFactory(initTimeout time.Duration, registrySize int, register func(*glua.LState), validate func(*glua.LState) error) LStateFactory {
	return func(ctx context.Context) (*glua.LState, error) {
		initCtx, cancel := context.WithTimeout(ctx, initTimeout)
		defer cancel()
		return p.NewState(initCtx, registrySize, register, validate)
	}
}
