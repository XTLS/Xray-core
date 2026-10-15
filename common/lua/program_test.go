package lua

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"weak"

	xerrors "github.com/xtls/xray-core/common/errors"
	glua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

func TestProgramStatesAreIndependent(t *testing.T) {
	path := writeTestScript(t, "value = (value or 0) + 1")
	program, err := Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	if program.proto.SourceName != path {
		t.Fatalf("program source = %q, want %q", program.proto.SourceName, path)
	}
	first, err := program.NewState(context.Background(), 256, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetGlobal("value", glua.LNumber(42))
	second, err := program.NewState(context.Background(), 256, nil, nil)
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
	state, err := program.NewState(ctx, 256, nil, nil)
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
	L, err := program.NewState(context.Background(), 256, nil, func(L *glua.LState) error {
		checked = L
		return wantErr
	})
	if L != nil || !errors.Is(err, wantErr) || checked == nil || !checked.IsClosed() {
		t.Fatalf("state = %v, error = %v, checked state closed = %t", L, err, checked != nil && checked.IsClosed())
	}
}

// TODO: Re-enable these tests and their helper when Compile supports inline scripts again.
/*
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
			state, err := program.NewState(context.Background(), 256, nil, nil)
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
		{"\n-- @xray:privileged-signature=invalid\n\nerror('failure')", false, "[inline]:4: failure"},
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
			state, initErr := program.NewState(context.Background(), 256, nil, nil)
			if state != nil {
				state.Close()
				t.Fatal("NewState returned a state after failed initialization")
			}
			err = initErr
		}
		if err == nil || !strings.Contains(err.Error(), "[inline]") {
			t.Fatalf("Lua error = %v, want [inline] diagnostic", err)
		}
		if tc.wantMessage != "" && !strings.Contains(err.Error(), tc.wantMessage) {
			t.Fatalf("Lua error = %v, want %q", err, tc.wantMessage)
		}
	}
}
*/

func TestCompileFileExtension(t *testing.T) {
	for _, name := range []string{"script", "script.dat", "script.lua.txt", "script.LUA"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte("value = 42"), 0o600); err != nil {
			t.Fatal(err)
		}
		if program, err := Compile(path); program != nil || err == nil || !strings.Contains(err.Error(), "Lua file extension must be .lua") {
			t.Fatalf("Compile(%q) = %v, %v; want nil program and .lua extension error", path, program, err)
		}
	}
	path := writeTestScript(t, "value = 42") + string(filepath.Separator) + "."
	if program, err := Compile(path); program == nil || err != nil {
		t.Fatalf("Compile(%q) = %v, %v; want acceptance of the resolved .lua path", path, program, err)
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
	program, err := Compile(writeTestScript(t, code))
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func writeTestScript(t *testing.T, code string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.lua")
	if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// TODO: Re-enable these tests and helpers when Compile supports privileged signature authorization again.
/*
const privilegedSignatureHeader = "-- @xray:privileged-signature="

// RFC 8032 test-vector key. The fixture signature was independently computed
// with Node's OpenSSL-backed crypto.sign(null, SHA256(body), privateKey), rather
// than by the signing helper or the production verifier.
const (
	privilegedTestSeed         = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	privilegedTestPublicKey    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	privilegedFixtureSignature = "rFbZtaaphe_69UEgSvfYwZcLZYHTXLFxdcukfEuLq6pzvmj8qtw6r60fD-7L5dwqSvnE7F1oAV0G_vHP3rLVBA"
	privilegedFixtureDigest    = "edef639ae641bacc9b76cea27473eed11369fbad65e223a87990864e899e578a"
	privilegedFixtureBody      = `-- Ordinary comments participate in the signed digest.
value = 1

function HasPrivilegedLibraries()
    return io ~= nil and os ~= nil and debug ~= nil and channel ~= nil
end`
)

func setTestPrivilegedPublicKey(t *testing.T, key string) {
	t.Helper()
	// Each test setup represents a new process with its own startup key.
	privilegedKey.Once = sync.Once{}
	privilegedKey.publicKey = nil
	t.Cleanup(func() {
		privilegedKey.Once = sync.Once{}
		privilegedKey.publicKey = nil
	})
	if err := SetPrivilegedPublicKey(key); err != nil {
		t.Fatal(err)
	}
}

func testSignature(t *testing.T, body string) string {
	t.Helper()
	seed, err := hex.DecodeString(privilegedTestSeed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes.TrimSpace([]byte(body)))
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), digest[:]))
}

func TestSetPrivilegedPublicKey(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	path := writeTestScript(t, privilegedSignatureHeader+privilegedFixtureSignature+"\n"+privilegedFixtureBody)
	for _, tc := range []struct{ name, key string }{
		{"invalid base64", "%"},
		{"padding", privilegedTestPublicKey + "="},
		{"standard base64 alphabet", strings.ReplaceAll(privilegedTestPublicKey, "_", "/")},
		{"short key", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize-1))},
		{"long key", base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize+1))},
		{"leading whitespace", " " + privilegedTestPublicKey},
		{"trailing whitespace", privilegedTestPublicKey + "\t"},
		{"embedded newline", privilegedTestPublicKey[:8] + "\n" + privilegedTestPublicKey[8:]},
		{"embedded carriage return", privilegedTestPublicKey[:8] + "\r" + privilegedTestPublicKey[8:]},
		{"nonzero unused bits", privilegedTestPublicKey[:len(privilegedTestPublicKey)-1] + "p"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := SetPrivilegedPublicKey(tc.key); err == nil {
				t.Fatal("invalid public key was accepted")
			}
			program, err := Compile(path)
			if err != nil || program == nil || !program.privileged {
				t.Fatalf("invalid setter changed the trusted key: Compile = %v, %v", program, err)
			}
		})
	}
	setTestPrivilegedPublicKey(t, "")
	if program, err := Compile(path); program != nil || err == nil {
		t.Fatalf("signed script after disabling authorization = %v, %v; want rejection", program, err)
	}
	unsigned, err := Compile(writeTestScript(t, privilegedFixtureBody))
	if err != nil || unsigned == nil || unsigned.privileged {
		t.Fatalf("unsigned script with authorization disabled = %v, %v; want sandbox", unsigned, err)
	}
}

func TestPrivilegedPublicKeyIsFixed(t *testing.T) {
	wrongKey := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	for _, key := range []string{"", privilegedTestPublicKey} {
		name := "disabled"
		if key != "" {
			name = "configured"
		}
		t.Run(name, func(t *testing.T) {
			setTestPrivilegedPublicKey(t, key)
			path := writeTestScript(t, privilegedSignatureHeader+privilegedFixtureSignature+"\n"+privilegedFixtureBody)
			for _, replacement := range []string{privilegedTestPublicKey, "", wrongKey} {
				if err := SetPrivilegedPublicKey(replacement); err != nil {
					t.Fatal(err)
				}
				program, err := Compile(path)
				if key == "" {
					if program != nil || err == nil {
						t.Fatalf("disabled startup key changed: Compile = %v, %v", program, err)
					}
				} else if err != nil || program == nil || !program.privileged {
					t.Fatalf("trusted startup key changed: Compile = %v, %v", program, err)
				}
			}
		})
	}
}

func TestProgramPrivilegedSignatureFixture(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	digest := sha256.Sum256([]byte(privilegedFixtureBody))
	if got := hex.EncodeToString(digest[:]); got != privilegedFixtureDigest {
		t.Fatalf("fixture SHA-256 = %s, want %s", got, privilegedFixtureDigest)
	}
	for _, signed := range []bool{false, true} {
		name, code := "unsigned", privilegedFixtureBody
		if signed {
			name, code = "signed", privilegedSignatureHeader+privilegedFixtureSignature+"\n"+code
		}
		t.Run(name, func(t *testing.T) {
			program, err := Compile(writeTestScript(t, code))
			if err != nil {
				t.Fatal(err)
			}
			if program.privileged != signed {
				t.Fatalf("privileged = %t, want %t", program.privileged, signed)
			}
			L, err := program.NewState(context.Background(), 256, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer L.Close()
			if err := L.CallByParam(glua.P{Fn: L.GetGlobal("HasPrivilegedLibraries"), NRet: 1, Protect: true}); err != nil {
				t.Fatal(err)
			}
			if got := L.Get(-1); got != glua.LBool(signed) {
				t.Fatalf("privileged libraries available = %v, want %t", got, signed)
			}
		})
	}
}

func TestProgramPrivilegedSignatureHeader(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	header := privilegedSignatureHeader + privilegedFixtureSignature
	for _, tc := range []struct {
		name, code string
		privileged bool
	}{
		{"match", header + "\n" + privilegedFixtureBody, true},
		{"no comment space", "--@xray:privileged-signature=" + privilegedFixtureSignature + "\n" + privilegedFixtureBody, true},
		{"comment whitespace", "-- \t  @xray:privileged-signature=" + privilegedFixtureSignature + "\n" + privilegedFixtureBody, true},
		{"signature whitespace", privilegedSignatureHeader + " \t" + privilegedFixtureSignature + " \t\n" + privilegedFixtureBody, true},
		{"blank lines and indentation", " \t\r\n\n \t" + header + "\n" + privilegedFixtureBody, true},
		{"CRLF header only", "\r\n" + header + "\r\n" + privilegedFixtureBody, true},
		{"body boundary whitespace", header + "\n \t\r\n\n" + privilegedFixtureBody + " \t\r\n\n", true},
		{"missing header", privilegedFixtureBody, false},
		{"after comment", "-- ordinary comment\n" + header + "\n" + privilegedFixtureBody, false},
		{"after code", "value = 1\n" + header + "\n" + privilegedFixtureBody, false},
		{"inside string", `value = "` + header + `"`, false},
		{"wrong marker", "-- xray:privileged-signature=" + privilegedFixtureSignature + "\n" + privilegedFixtureBody, false},
		{"invalid marker after comment", "-- ordinary comment\n" + privilegedSignatureHeader + "%\nvalue = 1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := Compile(writeTestScript(t, tc.code))
			if err != nil {
				t.Fatal(err)
			}
			if program.privileged != tc.privileged {
				t.Fatalf("privileged = %t, want %t", program.privileged, tc.privileged)
			}
		})
	}
}

func TestProgramRejectsInvalidPrivilegedSignatures(t *testing.T) {
	seed, err := hex.DecodeString(privilegedTestSeed)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	bodySignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(privilegedFixtureBody)))
	for _, tc := range []struct{ name, key, signature string }{
		{"missing key", "", privilegedFixtureSignature},
		{"wrong key", wrongKey, privilegedFixtureSignature},
		{"empty signature", privilegedTestPublicKey, ""},
		{"whitespace-only signature", privilegedTestPublicKey, " \t"},
		{"invalid base64", privilegedTestPublicKey, "%"},
		{"padding", privilegedTestPublicKey, privilegedFixtureSignature + "=="},
		{"standard base64 alphabet", privilegedTestPublicKey, strings.ReplaceAll(privilegedFixtureSignature, "_", "/")},
		{"short signature", privilegedTestPublicKey, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize-1))},
		{"long signature", privilegedTestPublicKey, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize+1))},
		{"embedded carriage return", privilegedTestPublicKey, privilegedFixtureSignature[:8] + "\r" + privilegedFixtureSignature[8:]},
		{"nonzero unused bits", privilegedTestPublicKey, privilegedFixtureSignature[:len(privilegedFixtureSignature)-1] + "B"},
		{"damaged signature", privilegedTestPublicKey, "s" + privilegedFixtureSignature[1:]},
		{"signature over body instead of digest", privilegedTestPublicKey, bodySignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setTestPrivilegedPublicKey(t, tc.key)
			program, err := Compile(writeTestScript(t, privilegedSignatureHeader+tc.signature+"\n"+privilegedFixtureBody))
			if program != nil || err == nil {
				t.Fatalf("Compile = %v, %v; want nil program and signature rejection", program, err)
			}
		})
	}
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	code := privilegedSignatureHeader + "%\n" + privilegedSignatureHeader + privilegedFixtureSignature + "\n" + privilegedFixtureBody
	if program, err := Compile(writeTestScript(t, code)); program != nil || err == nil {
		t.Fatalf("later signature replaced invalid first signature: %v, %v", program, err)
	}
}

func TestProgramSignedBodyTampering(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	for _, tc := range []struct{ name, body string }{
		{"statement", strings.Replace(privilegedFixtureBody, "value = 1", "value = 2", 1)},
		{"comment", strings.Replace(privilegedFixtureBody, "Ordinary", "Modified", 1)},
		{"added comment", "-- added comment\n" + privilegedFixtureBody},
		{"indentation", strings.Replace(privilegedFixtureBody, "    return", "  return", 1)},
		{"internal spaces", strings.Replace(privilegedFixtureBody, "value = 1", "value  = 1", 1)},
		{"internal trailing spaces", strings.Replace(privilegedFixtureBody, "value = 1\n", "value = 1 \t\n", 1)},
		{"removed blank line", strings.Replace(privilegedFixtureBody, "\n\n", "\n", 1)},
		{"added blank line", strings.Replace(privilegedFixtureBody, "\n\n", "\n\n\n", 1)},
		{"LF to CRLF", strings.ReplaceAll(privilegedFixtureBody, "\n", "\r\n")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := privilegedSignatureHeader + privilegedFixtureSignature + "\n" + tc.body
			if program, err := Compile(writeTestScript(t, code)); program != nil || err == nil {
				t.Fatalf("tampered body Compile = %v, %v; want signature rejection", program, err)
			}
		})
	}
	crlfBody := strings.ReplaceAll(privilegedFixtureBody, "\n", "\r\n")
	crlfSignature := testSignature(t, crlfBody)
	program, err := Compile(writeTestScript(t, privilegedSignatureHeader+crlfSignature+"\r\n"+crlfBody))
	if err != nil || program == nil || !program.privileged {
		t.Fatalf("correctly signed CRLF body = %v, %v; want privileged program", program, err)
	}
	if program, err := Compile(writeTestScript(t, privilegedSignatureHeader+crlfSignature+"\n"+privilegedFixtureBody)); program != nil || err == nil {
		t.Fatalf("CRLF to LF tampering = %v, %v; want signature rejection", program, err)
	}
}

*/

// TODO: Re-enable this test when Compile supports inline scripts again.
/*
func TestProgramInlineSignaturesCannotAuthorize(t *testing.T) {
	for _, key := range []string{"", privilegedTestPublicKey} {
		setTestPrivilegedPublicKey(t, key)
		for _, signature := range []string{privilegedFixtureSignature, "%", ""} {
			code := privilegedSignatureHeader + signature + "\n" + privilegedFixtureBody
			for _, script := range []string{
				xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code)),
				xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(compressSource(t, code)),
			} {
				program, err := Compile(script)
				if err != nil || program == nil || program.privileged {
					t.Fatalf("inline signed source Compile = %v, %v; want sandbox without verification", program, err)
				}
				L, err := program.NewState(context.Background(), 256, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				if got := L.GetGlobal("os"); got != glua.LNil {
					L.Close()
					t.Fatalf("inline os = %v, want nil", got)
				}
				L.Close()
			}
		}
	}
}
*/

// TODO: Re-enable this test when Compile supports privileged signature authorization again.
/*
func TestProgramSignedDiagnostics(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	const invalidBody = "\n\nlocal = 1"
	invalidPath := writeTestScript(t, "\n"+privilegedSignatureHeader+"%\n"+invalidBody)
	if program, err := Compile(invalidPath); program != nil || err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("invalid signature and invalid syntax = %v, %v; want signature error before parsing", program, err)
	}
	validPath := writeTestScript(t, "\n"+privilegedSignatureHeader+testSignature(t, invalidBody)+"\n"+invalidBody)
	if program, err := Compile(validPath); program != nil || err == nil || !strings.Contains(err.Error(), validPath+" line:5(") {
		t.Fatalf("verified invalid syntax = %v, %v; want original source line 5", program, err)
	}
	const body = "\n\nerror('signed failure')"
	path := writeTestScript(t, "\n"+privilegedSignatureHeader+testSignature(t, body)+"\n"+body)
	program, err := Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	L, err := program.NewState(context.Background(), 256, nil, nil)
	if L != nil {
		L.Close()
		t.Fatal("failing signed script returned a state")
	}
	if err == nil || !strings.Contains(err.Error(), path+":5: signed failure") {
		t.Fatalf("signed initialization error = %v; want original source line 5", err)
	}
}

*/

func TestProgramSandbox(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "escape.lua"), []byte(`disk_loaded = true; return "escaped"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUA_PATH", filepath.ToSlash(filepath.Join(dir, "?.lua")))
	program := compileTestProgram(t, `
local function check()
    assert(package == nil)
    assert(require("_G") == _G)
    for _, name in ipairs({"io", "debug", "channel", "ch", "coroutine", "dofile", "loadfile",
        "load", "loadstring", "getfenv", "setfenv", "collectgarbage", "module",
        "getmetatable", "setmetatable", "rawget", "rawset", "newproxy", "print", "_printregs"}) do
        assert(_G[name] == nil, name)
    end
    for _, name in ipairs({"io", "debug", "channel", "ch", "coroutine", "package", "escape"}) do
        assert(not pcall(require, name), name)
    end
    for _, name in ipairs({"math", "string", "table", "os"}) do
        assert(require(name) == _G[name], name)
    end
    for _, lib in ipairs({os, require("os")}) do
        for _, name in ipairs({"clock", "date", "difftime", "time"}) do
            assert(type(lib[name]) == "function", "os." .. name)
        end
        for _, name in ipairs({"execute", "exit", "getenv", "remove", "rename", "setenv", "setlocale", "tmpname"}) do
            assert(lib[name] == nil, "os." .. name)
        end
    end
    assert(string.dump == nil and ("").dump == nil and require("string").dump == nil)
    assert(math.randomseed == nil and require("math").randomseed == nil)
    local helper = require("xray.test")
    assert(helper.value == "ok" and helper == require("xray.test"))
    assert(math.abs(-2) == 2 and string.upper("ok") == "OK")
    assert(table.concat({"a", "b"}) == "ab")
end
check()
function CheckSandbox()
    check()
    local injected = false
    package = {
        preload = {
            escape = function() injected = true; return "escaped" end,
            ["xray.late"] = function() injected = true; return "injected" end,
        },
        loaded = {escape = "escaped", ["cached.only"] = "injected"},
        loaders = {function() injected = true; return function() return "escaped" end end},
        path = testPath,
        cpath = testPath,
    }
    assert(not pcall(require, "escape") and disk_loaded == nil)
    assert(not pcall(require, "cached.only") and not pcall(require, "package"))
    assert(require("xray.late") == "host" and require("xray.late") == "host")
    assert(require("xray.test").value == "ok" and not injected)
    package = nil
end`)
	var helperLoads, lateLoads int
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		if L.GetGlobal("io") != glua.LNil || L.GetGlobal("loadfile") != glua.LNil {
			t.Fatal("sandbox was not configured before module registration")
		}
		L.SetGlobal("testPath", glua.LString(filepath.ToSlash(filepath.Join(dir, "?.lua"))))
		L.PreloadModule("xray.test", func(L *glua.LState) int {
			helperLoads++
			module := L.NewTable()
			module.RawSetString("value", glua.LString("ok"))
			L.Push(module)
			return 1
		})
		L.PreloadModule("xray.late", func(L *glua.LState) int {
			lateLoads++
			L.Push(glua.LString("host"))
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
	if helperLoads != 1 || lateLoads != 1 {
		t.Fatalf("module initialization calls = (%d, %d), want (1, 1)", helperLoads, lateLoads)
	}
}

func TestProgramSandboxToString(t *testing.T) {
	program := compileTestProgram(t, `
assert(tostring == require("_G").tostring)
for _, convert in ipairs({tostring, require("_G").tostring}) do
    assert(convert(nil) == "nil")
    assert(convert(true) == "true" and convert(false) == "false")
    assert(convert(0) == "0" and convert(-42) == "-42" and convert(1.25) == "1.25")
    assert(convert("") == "" and convert("hello") == "hello")
    assert(convert("0xdeadbeef") == "0xdeadbeef")
    assert(convert(42, {}) == "42")
    assert(not pcall(convert))
    assert(convert(testIPv4) == "192.0.2.1")
    assert(convert(testIPv6) == "2001:db8::1")
    assert(convert(testNativeIP) == "198.51.100.1")
    assert(convert(testNativeStringer) == "0xdeadbeef")
    assert(convert(testNativeError) == "lookup failed")
    for _, value in ipairs({{}, function() end, convert, testUserdata, testThread, testChannel, testGoStruct, testIPs}) do
        local ok, result = pcall(convert, value)
        assert(ok and result == "<opaque>")
    end
end
string.__tostring = function() error("string __tostring must not run") end
assert(tostring("hello") == "hello")
string.__tostring = nil
`)
	var metamethodCalls int
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		L.SetGlobal("testIPv4", luar.New(L, net.ParseIP("192.0.2.1")))
		L.SetGlobal("testIPv6", luar.New(L, net.ParseIP("2001:db8::1")))
		PushUserData(L, net.ParseIP("198.51.100.1"))
		L.SetGlobal("testNativeIP", L.Get(-1))
		L.Pop(1)
		PushUserData(L, bytes.NewBufferString("0xdeadbeef"))
		L.SetGlobal("testNativeStringer", L.Get(-1))
		L.Pop(1)
		PushError(L, errors.New("lookup failed"))
		L.SetGlobal("testNativeError", L.Get(-1))
		L.Pop(1)
		L.SetGlobal("testGoStruct", luar.New(L, &struct{ Value string }{"readable field"}))
		NewSlicePusher[net.IP](L)(L, []net.IP{net.ParseIP("192.0.2.1")})
		L.SetGlobal("testIPs", L.Get(-1))
		L.Pop(1)
		userdata := L.NewUserData()
		metatable := L.NewTable()
		metatable.RawSetString("__tostring", L.NewFunction(func(L *glua.LState) int {
			metamethodCalls++
			L.Push(glua.LString("custom"))
			return 1
		}))
		L.SetMetatable(userdata, metatable)
		L.SetGlobal("testUserdata", userdata)
		thread, cancel := L.NewThread()
		if cancel != nil {
			t.Cleanup(cancel)
		}
		L.SetGlobal("testThread", thread)
		L.SetGlobal("testChannel", glua.LChannel(make(chan glua.LValue)))
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	if metamethodCalls != 0 {
		t.Fatalf("__tostring calls = %d, want 0", metamethodCalls)
	}
}

func TestProgramSandboxStringFormat(t *testing.T) {
	program := compileTestProgram(t, `
assert(string.format == require("string").format and string.format == ("").format)
for _, format in ipairs({string.format, require("string").format, ("").format}) do
    assert(format("%s %04d %.2f %t", "hello", 42, 1.25, true) == "hello 0042 1.25 true")
    assert(format("%q", "hello") == '"hello"')
    assert(format("%s", "0xdeadbeef") == "0xdeadbeef")
    assert(format("%[2]s:%[1]d", 42, "hello") == "hello:42")
    assert(format("%%p") == "%p")
    assert(format("%%p", {}) == format("%%p", "<opaque>"))
    assert(format("%s", 42) == "42")
    assert(format("%s", nil) == "nil")
    assert(format("%s", testIP) == "192.0.2.1")
    assert(format("%#v", testIP) == '"192.0.2.1"')
    assert(format("%p", testIP) == format("%p", "192.0.2.1"))
    assert(format("%s", testNativeStringer) == "0xdeadbeef")
    assert(format("%s", testNativeError) == "lookup failed")
    assert(not pcall(format))
    for _, value in ipairs({{}, function() end, format, testUserdata, testThread, testChannel}) do
        assert(format("%s", value) == "<opaque>")
        assert(format("%v", value) == "<opaque>")
        assert(format("%q", value) == '"<opaque>"')
        assert(format("%#v", value) == '"<opaque>"')
        for _, pattern in ipairs({"%p", "%#p", "%+020p", "%[1]p", "%[1]p %#[1]v",
            "%x", "%X", "%#x", "%d", "%t", "%w"}) do
            local result = format(pattern, value)
            assert(result == format(pattern, "<opaque>"), pattern .. ": " .. result)
        end
    end
    assert(format("%p", nil) == format("%p", "nil"))
end
assert(("%s"):format({}) == "<opaque>")
`)
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		L.SetGlobal("testIP", luar.New(L, net.ParseIP("192.0.2.1")))
		PushUserData(L, bytes.NewBufferString("0xdeadbeef"))
		L.SetGlobal("testNativeStringer", L.Get(-1))
		L.Pop(1)
		PushError(L, errors.New("lookup failed"))
		L.SetGlobal("testNativeError", L.Get(-1))
		L.Pop(1)
		userdata := L.NewUserData()
		metatable := L.NewTable()
		metatable.RawSetString("__tostring", L.NewFunction(func(L *glua.LState) int {
			t.Error("string.format must not call __tostring")
			L.Push(glua.LString("custom"))
			return 1
		}))
		L.SetMetatable(userdata, metatable)
		L.SetGlobal("testUserdata", userdata)
		thread, cancel := L.NewThread()
		if cancel != nil {
			t.Cleanup(cancel)
		}
		L.SetGlobal("testThread", thread)
		L.SetGlobal("testChannel", glua.LChannel(make(chan glua.LValue)))
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	if L.GetTop() != 0 {
		t.Fatalf("stack top = %d, want 0", L.GetTop())
	}
}

func TestProgramSandboxProtectedCalls(t *testing.T) {
	program := compileTestProgram(t, `
assert(pcall == require("_G").pcall and xpcall == require("_G").xpcall)
local object = {}
local function succeed(a, b, c)
    assert(a == 42 and b == nil and c == object)
    return nil, object, "0xdeadbeef"
end
local ok, a, b, c = pcall(succeed, 42, nil, object)
assert(ok and a == nil and b == object and c == "0xdeadbeef")
assert(select("#", pcall(succeed, 42, nil, object)) == 4)
local function noArguments(...)
    assert(select("#", ...) == 0)
    return nil, object, nil
end
local function unexpectedHandler() error("handler must not run") end
ok, a, b, c = xpcall(noArguments, unexpectedHandler, "ignored")
assert(ok and a == nil and b == object and c == nil)
assert(select("#", xpcall(noArguments, unexpectedHandler)) == 4)
ok, a = pcall(testCallable, 42)
assert(ok and a == 42)
ok, a = pcall(nil)
assert(not ok and a == "attempt to call a nil value")
ok, a = pcall(pcall)
assert(not ok and string.find(a, "bad argument #1", 1, true))
ok, a = pcall(xpcall, nil, nil)
assert(not ok and string.find(a, "bad argument #1", 1, true))
ok, a = pcall(xpcall, noArguments, nil)
assert(not ok and string.find(a, "bad argument #2", 1, true))

local businessError = "DNS lookup timed out (192.0.2.1)"
ok, a = pcall(error, businessError, 0)
assert(not ok and a == businessError)
ok, a = xpcall(function() error(businessError, 0) end, function(message)
    assert(message == businessError)
    return "handled: " .. message, "ignored"
end)
assert(not ok and a == "handled: " .. businessError)
local message = "lookup at 0x12Ab / 0XFE90; 2001:db8::1; 0x"
local redacted = "lookup at <address> / <address>; 2001:db8::1; 0x"
ok, a = pcall(error, message, 0)
assert(not ok and a == redacted)
ok, a = pcall(error, "business id=0xdeadbeef", 0)
assert(not ok and a == "business id=<address>")
for _, value in ipairs({object, testObject, true, 42}) do
    ok, a = pcall(error, value, 0)
    assert(not ok and a == value)
    ok, a = xpcall(function() error(value, 0) end, function(caught)
        assert(caught == value)
        return caught
    end)
    assert(not ok and a == value)
end
ok, a = pcall(error, nil, 0)
assert(not ok and a == nil)

local conversion = "cannot use function: <address> (type *lua.LFunction) as type string"
ok, a = pcall(testTakeString, function() end)
assert(not ok and string.find(a, conversion, 1, true))
ok, a = xpcall(function() testTakeString(function() end) end, function(caught)
    testSendError(caught)
    return caught
end)
assert(not ok and string.find(a, conversion, 1, true))
ok, a = pcall(function() testValues[1] = testObject end)
assert(not ok and string.find(a, "<address>", 1, true) and not string.find(a, "0x", 1, true))
assert(string.find(a, "as type int", 1, true))
testValues[1] = 7
local extended = testValues + 9
assert(testValues[1] == 7 and #extended == 2 and extended[2] == 9)
ok, a = pcall(testPanic)
assert(not ok and a == "{<address> <address>}")
ok, a = xpcall(testPanic, function(caught)
    testSendError(caught)
    return caught
end)
assert(not ok and a == "{<address> <address>}")
ok, a = xpcall(function() error(message, 0) end, function(caught)
    assert(caught == redacted)
    error("handler failed at 0xABCD", 0)
end)
assert(not ok and a == "handler failed at <address>")
ok, a = xpcall(function() error(businessError, 0) end, testPanic)
assert(not ok and a == "{<address> <address>}")
`)
	var sent []string
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		callable := L.NewTable()
		metatable := L.NewTable()
		metatable.RawSetString("__call", L.NewFunction(func(L *glua.LState) int {
			L.Push(L.Get(2))
			return 1
		}))
		L.SetMetatable(callable, metatable)
		L.SetGlobal("testCallable", callable)
		L.SetGlobal("testTakeString", luar.New(L, func(string) {}))
		target := 42
		PushUserData(L, struct{ Pointer *int }{&target})
		L.SetGlobal("testObject", L.Get(-1))
		L.Pop(1)
		NewSlicePusher[int](L)(L, []int{1})
		L.SetGlobal("testValues", L.Get(-1))
		L.Pop(1)
		L.SetGlobal("testPanic", L.NewFunction(func(L *glua.LState) int {
			panic(struct{ First, Second *int }{&target, &target})
		}))
		L.SetGlobal("testSendError", L.NewFunction(func(L *glua.LState) int {
			message := L.CheckString(1)
			if strings.Contains(message, "0x") || strings.Contains(message, "0X") {
				t.Errorf("outbound error contains an address: %q", message)
			}
			sent = append(sent, message)
			return 0
		}))
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	if len(sent) != 2 || !strings.Contains(sent[0], "cannot use function: <address>") || sent[1] != "{<address> <address>}" {
		t.Fatalf("outbound errors = %q", sent)
	}
	if L.GetTop() != 0 {
		t.Fatalf("stack top = %d, want 0", L.GetTop())
	}
}

func TestProgramSandboxGoErrorStrings(t *testing.T) {
	program := compileTestProgram(t, `
for name, expected in pairs(testErrorMessages) do
    local value = _G[name]
    assert(tostring(value) == expected, name)
    assert(string.format("%s", value) == expected, name)
    assert(string.format("%p", value) == string.format("%p", expected), name)
    assert(string.format("%#v", value) == string.format("%#v", expected), name)
    local ok, caught = pcall(error, value, 0)
    assert(not ok and caught == value and tostring(caught) == expected, name)
    ok, caught = xpcall(function() error(value, 0) end, function(caught)
        assert(caught == value and tostring(caught) == expected, name)
        return caught
    end)
    assert(not ok and caught == value, name)
end
`)
	nativeErrors := make(map[string]error)
	originalMessages := make(map[string]string)
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		luaError := &glua.ApiError{Object: L.NewFunction(func(*glua.LState) int { return 0 })}
		stringerError := xerrors.New("DNS query failed").Base(luaError)
		messages := L.NewTable()
		for _, tc := range []struct {
			name     string
			err      error
			expected string
		}{
			{"nativeError", errors.New("lookup failed at 0x12Ab and 0XFe90"), "lookup failed at <address> and <address>"},
			{"luaError", luaError, "function: <address>"},
			{"wrappedError", fmt.Errorf("DNS query failed: %w", luaError), "DNS query failed: function: <address>"},
			{"stringerError", stringerError, strings.ReplaceAll(stringerError.Error(), luaError.Object.String(), "function: <address>")},
		} {
			nativeErrors[tc.name] = tc.err
			originalMessages[tc.name] = tc.err.Error()
			PushError(L, tc.err)
			L.SetGlobal(tc.name, L.Get(-1))
			L.Pop(1)
			messages.RawSetString(tc.name, glua.LString(tc.expected))
		}
		L.SetGlobal("testErrorMessages", messages)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	for name, native := range nativeErrors {
		if got := ReadError(L.GetGlobal(name), "invalid"); got != native {
			t.Fatalf("%s error identity changed", name)
		}
		if got := native.Error(); got != originalMessages[name] {
			t.Fatalf("%s host error = %q, want %q", name, got, originalMessages[name])
		}
	}
}

func TestProgramSandboxModuleFailures(t *testing.T) {
	program := compileTestProgram(t, `
assert(package == nil)
local ok, err = pcall(require, "xray.failure")
assert(not ok and string.find(err, "module initialization failed", 1, true))
package = {loaded = {["xray.failure"] = "injected"}}
ok, err = pcall(require, "xray.failure")
assert(not ok and string.find(err, "loop or previous error loading module", 1, true))
for i = 1, 2 do
    ok, err = pcall(require, "xray.cycle")
    assert(not ok and string.find(err, "loop or previous error loading module", 1, true))
end
package = nil
`)
	var failedLoads, cycleLoads int
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		L.PreloadModule("xray.failure", func(L *glua.LState) int {
			failedLoads++
			L.RaiseError("module initialization failed")
			return 0
		})
		L.PreloadModule("xray.cycle", func(L *glua.LState) int {
			cycleLoads++
			L.Push(L.GetGlobal("require"))
			L.Push(glua.LString("xray.cycle"))
			L.Call(1, 1)
			return 1
		})
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer L.Close()
	if failedLoads != 1 || cycleLoads != 1 {
		t.Fatalf("module initialization calls = (%d, %d), want (1, 1)", failedLoads, cycleLoads)
	}
	if L.GetTop() != 0 {
		t.Fatalf("stack top = %d, want 0", L.GetTop())
	}
}

func TestProgramSandboxModulesAreCollected(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			ref := func() weak.Pointer[glua.LTable] {
				program := compileTestProgram(t, `payload = string.rep("x", 1024 * 1024); assert(pcall(require, "xray.test") == expectedSuccess)`)
				L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
					L.SetGlobal("expectedSuccess", glua.LBool(!fail))
					L.PreloadModule("xray.test", func(L *glua.LState) int {
						if fail {
							L.RaiseError("module initialization failed")
						}
						L.Push(L.NewTable())
						return 1
					})
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				ref := weak.Make(L.G.Global)
				L.Close()
				return ref
			}()
			runtime.GC()
			runtime.GC()
			if ref.Value() != nil {
				t.Fatal("closed sandbox's global table was not collected")
			}
		})
	}
}

func TestProgramSandboxClosesFailedInitialization(t *testing.T) {
	program := compileTestProgram(t, `require("xray.failure")`)
	var partial *glua.LState
	L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
		partial = L
		L.PreloadModule("xray.failure", func(L *glua.LState) int {
			L.RaiseError("module initialization failed")
			return 0
		})
	}, func(*glua.LState) error {
		t.Error("validation ran after failed initialization")
		return nil
	})
	if L != nil {
		L.Close()
		t.Fatal("sandbox initialization returned a state")
	}
	if err == nil || !strings.Contains(err.Error(), "module initialization failed") || partial == nil || !partial.IsClosed() {
		t.Fatalf("error = %v, partial state closed = %t", err, partial != nil && partial.IsClosed())
	}
}

// TODO: Re-enable these tests when Compile supports privileged signature authorization again.
/*
func TestProgramPrivilegedLibraries(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	const body = `assert(require("io") == io and require("os") == os)
assert(require("debug") == debug and require("channel") == channel)
assert(type(coroutine.create) == "function" and require("coroutine") == coroutine)
assert(type(dofile) == "function" and type(loadfile) == "function")
assert(type(getfenv) == "function" and type(setfenv) == "function")
assert(type(collectgarbage) == "function" and type(print) == "function")
assert(type(getmetatable) == "function" and type(setmetatable) == "function")
assert(type(rawget) == "function" and type(rawset) == "function")
assert(tostring(42) == "42" and type(tostring({})) == "string")
assert(tostring(setmetatable({}, {__tostring = function() return "custom" end})) == "custom")
local ok, message = pcall(error, "lookup failed at 0x12Ab", 0)
assert(not ok and message == "lookup failed at 0x12Ab")
ok, message = xpcall(function() error("lookup failed at 0x12Ab", 0) end, function(caught)
    assert(caught == "lookup failed at 0x12Ab")
    return caught
end)
assert(not ok and message == "lookup failed at 0x12Ab")
assert(type(string.dump) == "function" and type(math.randomseed) == "function")
assert(type(package.loaders[2]) == "function" and type(package.path) == "string")
assert(type(debug.traceback()) == "string" and type(os.time()) == "number")
assert(assert(loadstring("return 42"))() == 42)
local file = assert(io.open(testPath, "w"))
file:write("privileged")
file:close()`
	code := privilegedSignatureHeader + testSignature(t, body) + "\n" + body
	path := filepath.Join(t.TempDir(), "privileged.lua")
	if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, script string
		privileged   bool
	}{
		{"file", path, true},
		// TODO: Re-enable these cases when Compile supports inline scripts again.
		// {"base64", xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code)), false},
		// {"gzip", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(compressSource(t, code)), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			program, err := Compile(tc.script)
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "privileged.txt")
			L, err := program.NewState(context.Background(), 256, func(L *glua.LState) {
				L.SetGlobal("testPath", glua.LString(output))
			}, nil)
			if !tc.privileged {
				if L != nil {
					L.Close()
					t.Fatal("inline script with a valid signature accessed privileged libraries")
				}
				if err == nil || !strings.Contains(err.Error(), "no preloaded module: io") {
					t.Fatalf("NewState error = %v, want io module unavailable", err)
				}
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("inline script output stat error = %v, want file not found", err)
				}
				return
			}
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
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	for _, privileged := range []bool{false, true} {
		name := "sandboxed"
		if privileged {
			name = "privileged"
		}
		t.Run(name, func(t *testing.T) {
			const body = "value = 1"
			code := body
			if privileged {
				code = privilegedSignatureHeader + testSignature(t, body) + "\n" + body
			}
			path := filepath.Join(t.TempDir(), "snapshot.lua")
			if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			program, err := Compile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Source edits cannot change an already compiled Program's authorization.
			changed := privilegedSignatureHeader + testSignature(t, body) + "\n" + body
			if privileged {
				changed = body
			}
			if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			check := func(L *glua.LState) {
				t.Helper()
				if got := L.GetField(L.GetGlobal("os"), "execute").Type() == glua.LTFunction; got != privileged {
					t.Fatalf("os.execute available = %t, want compile-time value %t", got, privileged)
				}
			}
			factory := program.NewStateFactory(time.Second, 256, nil, nil)
			for range 2 {
				L, err := factory(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer L.Close()
				check(L)
			}
			recompiled, err := Compile(path)
			if err != nil {
				t.Fatal(err)
			}
			if recompiled.privileged == privileged {
				t.Fatal("recompilation did not observe the changed source")
			}
		})
	}
}
*/
