package lua

import (
	"bytes"
	"context"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/common/platform"
	glua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Program holds immutable bytecode that can be run by independent LStates.
type Program struct {
	proto *glua.FunctionProto
}

// LStateFactory returns a fully initialized state or nil and an error.
// Implementations must close partial states on failure; callers own successful states.
type LStateFactory func(context.Context) (*glua.LState, error)

// Compile reads a Lua file or decodes an inline script and compiles it into an immutable program.
func Compile(script string) (*Program, error) {
	var code []byte
	var err error
	name := "[inline]"
	if strings.HasPrefix(script, base64.GzipPrefix) || strings.HasPrefix(script, base64.Prefix) {
		code, err = base64.Decode(script)
	} else if name, err = platform.ResolveLuaFile(script); err == nil {
		code, err = os.ReadFile(name)
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
	return &Program{proto: proto}, nil
}

// NewState creates a state, runs register, executes the program under ctx, and
// runs validate. It removes the initialization context before returning a state
// owned by the caller.
func (p *Program) NewState(ctx context.Context, register func(*glua.LState), validate func(*glua.LState) error) (*glua.LState, error) {
	L := glua.NewState()
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

// NewStateFactory returns a factory that gives each state an initialization timeout.
func (p *Program) NewStateFactory(initTimeout time.Duration, register func(*glua.LState), validate func(*glua.LState) error) LStateFactory {
	return func(ctx context.Context) (*glua.LState, error) {
		initCtx, cancel := context.WithTimeout(ctx, initTimeout)
		defer cancel()
		return p.NewState(initCtx, register, validate)
	}
}
