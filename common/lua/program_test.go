package lua

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	xbase64 "github.com/xtls/xray-core/common/base64"
	glua "github.com/yuin/gopher-lua"
)

func TestProgramStatesAreIndependent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lua")
	if err := os.WriteFile(path, []byte("value = (value or 0) + 1"), 0o600); err != nil {
		t.Fatal(err)
	}
	program, err := Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	if program.proto.SourceName != path {
		t.Fatalf("program source = %q, want %q", program.proto.SourceName, path)
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
	program, err := Compile(path)
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
	program, err := Compile(path)
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

func compressSource(t *testing.T, code string) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := gzip.NewWriter(&data)
	if _, err := writer.Write([]byte(code)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestCompileInline(t *testing.T) {
	const code = `value = "你好"`
	for _, tc := range []struct {
		name, script string
		value        glua.LValue
	}{
		{"base64", xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code)), glua.LString("你好")},
		{"base64+gzip", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(compressSource(t, code)), glua.LString("你好")},
		{"empty base64", xbase64.Prefix, glua.LNil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := Compile(tc.script)
			if err != nil {
				t.Fatal(err)
			}
			if program.proto.SourceName != "[inline]" {
				t.Fatalf("program source = %q, want [inline]", program.proto.SourceName)
			}
			state, err := program.NewState(context.Background(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			if got := state.GetGlobal("value"); got != tc.value {
				t.Fatalf("value = %v, want %v", got, tc.value)
			}
		})
	}
}

func TestCompileRejectsInvalidInline(t *testing.T) {
	corrupt := compressSource(t, "value = 1")
	corrupt[len(corrupt)-8] ^= 0xff
	for _, tc := range []struct {
		name, script string
		wantErr      error
		wantMessage  string
	}{
		{"base64", xbase64.Prefix + "%", base64.CorruptInputError(0), "failed to decode base64"},
		{"gzip base64", xbase64.GzipPrefix + "%", base64.CorruptInputError(0), "failed to decode base64"},
		{"gzip header", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString([]byte("value = 'uncompressed'")), gzip.ErrHeader, "failed to decompress gzip"},
		{"gzip checksum", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(corrupt), gzip.ErrChecksum, "failed to decompress gzip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := Compile(tc.script)
			if program != nil || !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), tc.wantMessage) {
				t.Fatalf("Compile = %v, %v; want nil program and %q error wrapping %v", program, err, tc.wantMessage, tc.wantErr)
			}
		})
	}
}

func TestCompileInlineDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		code         string
		compileError bool
	}{
		{"function broken(", true},
		{`error("initialization failed")`, false},
	} {
		program, err := Compile(xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(tc.code)))
		if tc.compileError {
			if program != nil || err == nil {
				t.Fatalf("Compile = %v, %v; want nil program and syntax error", program, err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			state, initErr := program.NewState(context.Background(), nil, nil)
			if state != nil {
				state.Close()
				t.Fatal("NewState returned a state after failed initialization")
			}
			err = initErr
		}
		if err == nil || !strings.Contains(err.Error(), "[inline]") {
			t.Fatalf("Lua error = %v, want [inline] diagnostic", err)
		}
	}
}

func TestCompileRejectsReadFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unreadable.lua")
	if err := os.WriteFile(path, []byte("value = 42"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(path, 0o600) })
	if _, err := os.ReadFile(path); !errors.Is(err, os.ErrPermission) {
		t.Skip("file read permissions are not enforced")
	}
	if program, err := Compile(path); program != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("Compile = %v, %v; want nil program and permission error", program, err)
	}
}
