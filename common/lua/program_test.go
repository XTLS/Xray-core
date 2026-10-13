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
	"time"

	xbase64 "github.com/xtls/xray-core/common/base64"
	"github.com/xtls/xray-core/common/platform"
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
		wantMessage  string
	}{
		{"function broken(", true, ""},
		{`error("initialization failed")`, false, ""},
		{"\n-- @xray:privileged-psk=secret\n\nerror('failure')", false, "[inline]:4: failure"},
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
		if tc.wantMessage != "" && (!strings.Contains(err.Error(), tc.wantMessage) || strings.Contains(err.Error(), "secret")) {
			t.Fatalf("Lua error = %v, want %q without the PSK", err, tc.wantMessage)
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

func compileTestProgram(t *testing.T, code string) *Program {
	t.Helper()
	program, err := Compile(xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code)))
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestProgramPrivilegedPSK(t *testing.T) {
	const header = "-- @xray:privileged-psk="
	for _, tc := range []struct {
		name, psk, code string
		privileged      bool
	}{
		{"match", "secret", header + "secret", true},
		{"no comment space", "secret", "--@xray:privileged-psk=secret", true},
		{"comment whitespace", "secret", "-- \t  @xray:privileged-psk=secret", true},
		{"mismatch", "secret", header + "other", false},
		{"both empty", "", header, false},
		{"missing header", "secret", "value = 1", false},
		{"empty header", "secret", header, false},
		{"blank lines and indentation", "secret", " \t\n\n \t" + header + "secret", true},
		{"CRLF", "secret", "\r\n" + header + "secret\r\nvalue = 1\r\n", true},
		{"key whitespace", " \tsecret \t", header + " secret ", true},
		{"whitespace-only keys", " \t", header + " \t", false},
		{"after comment", "secret", "-- ordinary comment\n" + header + "secret", false},
		{"after code", "secret", "value = 1\n" + header + "secret", false},
		{"inside string", "secret", `value = "-- @xray:privileged-psk=secret"`, false},
		{"wrong marker", "secret", "-- xray:privileged-psk=secret", false},
		{"later match", "secret", header + "other\n" + header + "secret", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(platform.LuaPrivilegedPSK, tc.psk)
			program := compileTestProgram(t, tc.code)
			if program.privileged != tc.privileged {
				t.Fatalf("privileged = %t, want %t", program.privileged, tc.privileged)
			}
		})
	}
}

func TestProgramSandbox(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "escape.lua"), []byte(`disk_loaded = true; return "escaped"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUA_PATH", filepath.ToSlash(filepath.Join(dir, "?.lua")))
	program := compileTestProgram(t, `
local function check()
    assert(require("_G") == _G)
    for _, name in ipairs({"io", "os", "debug", "channel", "dofile", "loadfile",
        "load", "loadstring", "getfenv", "setfenv", "collectgarbage", "module",
        "newproxy", "print", "_printregs"}) do
        assert(_G[name] == nil, name)
    end
    for _, name in ipairs({"io", "os", "debug", "channel", "escape"}) do
        assert(package.loaded[name] == nil and package.preload[name] == nil, name)
        assert(not pcall(require, name), name)
    end
    for name in pairs(package) do
        assert(name == "preload" or name == "loaded" or name == "loaders", name)
    end
    assert(type(package.loaders[1]) == "function" and package.loaders[2] == nil)
    for _, name in ipairs({"math", "string", "table", "coroutine"}) do
        assert(require(name) == _G[name], name)
    end
    local helper = require("xray.test")
    assert(helper.value == "ok" and helper == require("xray.test"))
    assert(math.abs(-2) == 2 and string.upper("ok") == "OK")
    assert(table.concat({"a", "b"}) == "ab")
end
check()
function CheckSandbox()
    local thread = coroutine.create(check)
    assert(coroutine.resume(thread))
    package.path = testPath
    package.cpath = testPath
    assert(not pcall(require, "escape") and disk_loaded == nil)
    package.path = nil
    package.cpath = nil
end`)
	L, err := program.NewState(context.Background(), func(L *glua.LState) {
		if L.GetGlobal("io") != glua.LNil || L.GetGlobal("loadfile") != glua.LNil {
			t.Fatal("sandbox was not configured before module registration")
		}
		L.SetGlobal("testPath", glua.LString(filepath.ToSlash(filepath.Join(dir, "?.lua"))))
		L.PreloadModule("xray.test", func(L *glua.LState) int {
			module := L.NewTable()
			module.RawSetString("value", glua.LString("ok"))
			L.Push(module)
			return 1
		})
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	if L.GetTop() != 0 {
		t.Fatalf("stack top = %d, want 0", L.GetTop())
	}
	if err := L.CallByParam(glua.P{Fn: L.GetGlobal("CheckSandbox"), Protect: true}); err != nil {
		t.Fatal(err)
	}
}

func TestProgramSandboxClosesFailedInitialization(t *testing.T) {
	program := compileTestProgram(t, `require("io")`)
	var partial *glua.LState
	L, err := program.NewState(context.Background(), func(L *glua.LState) {
		partial = L
	}, func(*glua.LState) error {
		t.Error("validation ran after failed initialization")
		return nil
	})
	if L != nil {
		L.Close()
		t.Fatal("sandbox initialization returned a state")
	}
	if err == nil || partial == nil || !partial.IsClosed() {
		t.Fatalf("error = %v, partial state closed = %t", err, partial != nil && partial.IsClosed())
	}
}

func TestProgramPrivilegedLibraries(t *testing.T) {
	t.Setenv(platform.LuaPrivilegedPSK, "secret")
	const code = `-- @xray:privileged-psk=secret
assert(require("io") == io and require("os") == os)
assert(require("debug") == debug and require("channel") == channel)
assert(type(dofile) == "function" and type(loadfile) == "function")
assert(type(getfenv) == "function" and type(setfenv) == "function")
assert(type(collectgarbage) == "function" and type(print) == "function")
assert(type(package.loaders[2]) == "function" and type(package.path) == "string")
assert(type(debug.traceback()) == "string" and type(os.time()) == "number")
assert(assert(loadstring("return 42"))() == 42)
local file = assert(io.open(testPath, "w"))
file:write("privileged")
file:close()`
	path := filepath.Join(t.TempDir(), "privileged.lua")
	if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
	}{
		{"file", path},
		{"base64", xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code))},
		{"gzip", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(compressSource(t, code))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := Compile(tc.script)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "privileged.txt")
			L, err := program.NewState(context.Background(), func(L *glua.LState) {
				L.SetGlobal("testPath", glua.LString(output))
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer L.Close()
			data, err := os.ReadFile(output)
			if err != nil || string(data) != "privileged" {
				t.Fatalf("privileged file contents = %q, error = %v", data, err)
			}
		})
	}
}

func TestProgramPrivilegesAreCompileTimeSnapshot(t *testing.T) {
	for _, privileged := range []bool{false, true} {
		name := "sandboxed"
		if privileged {
			name = "privileged"
		}
		t.Run(name, func(t *testing.T) {
			before, after := "other", "secret"
			if privileged {
				before, after = after, before
			}
			t.Setenv(platform.LuaPrivilegedPSK, before)
			const code = "-- @xray:privileged-psk=secret\nvalue = 1"
			program := compileTestProgram(t, code)
			t.Setenv(platform.LuaPrivilegedPSK, after)
			check := func(L *glua.LState) {
				t.Helper()
				if got := L.GetGlobal("os").Type() == glua.LTTable; got != privileged {
					t.Fatalf("os available = %t, want compile-time value %t", got, privileged)
				}
			}
			factory := program.NewStateFactory(time.Second, nil, nil)
			for range 2 {
				L, err := factory(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer L.Close()
				check(L)
			}
			if recompiled := compileTestProgram(t, code); recompiled.privileged == privileged {
				t.Fatal("recompilation did not observe the changed environment")
			}
		})
	}
}
