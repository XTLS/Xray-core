// Package lua provides shared GopherLua programs and state management for Xray scripts.
package lua

import (
	"bufio"
	"context"
	"os"

	glua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// Program holds immutable bytecode that can be run by independent LStates.
type Program struct {
	proto *glua.FunctionProto
}

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

// NewState creates a VM, makes modules available, and executes the file top level.
// Module loaders run only when Lua calls require. Each state gets its own globals.
// The caller owns the returned state.
func (p *Program) NewState(ctx context.Context, register func(*glua.LState)) (*glua.LState, error) {
	L := glua.NewState()
	if register != nil {
		register(L)
	}
	L.SetContext(ctx)
	L.Push(L.NewFunctionFromProto(p.proto))
	err := L.PCall(0, 0, nil)
	L.RemoveContext()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		L.Close()
		return nil, err
	}
	return L, nil
}
