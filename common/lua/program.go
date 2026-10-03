package lua

import (
	"bufio"
	"context"
	"os"
	"time"

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

// CompileFile reads and compiles a Lua file once.
func CompileFile(path string) (*Program, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	chunk, err := parse.Parse(bufio.NewReader(f), path)
	if err != nil {
		return nil, err
	}
	proto, err := glua.Compile(chunk, path)
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
