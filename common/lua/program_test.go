package lua

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	glua "github.com/yuin/gopher-lua"
)

func TestProgramStatesAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lua")
	if err := os.WriteFile(path, []byte("value = (value or 0) + 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := CompileFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := program.NewState(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetGlobal("value", glua.LNumber(42))
	second, err := program.NewState(context.Background(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if got := second.GetGlobal("value"); got != glua.LNumber(1) {
		t.Fatalf("second state value = %v, want 1", got)
	}
}

func TestProgramInitializationObservesCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "loop.lua")
	if err := os.WriteFile(path, []byte("while true do end"), 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := CompileFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state, err := program.NewState(ctx, nil, nil)
	if err == nil || state != nil {
		if state != nil {
			state.Close()
		}
		t.Fatalf("NewState with canceled context = %v, %v; want nil state and error", state, err)
	}
}

func TestNewStateClosesFailedValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lua")
	if err := os.WriteFile(path, []byte("value = 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := CompileFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("invalid script")
	var checked *glua.LState
	L, err := program.NewState(context.Background(), nil, func(L *glua.LState) error {
		checked = L
		return wantErr
	})
	if L != nil || !errors.Is(err, wantErr) || checked == nil || !checked.IsClosed() {
		t.Fatalf("state = %v, error = %v, checked state closed = %t", L, err, checked != nil && checked.IsClosed())
	}
}
