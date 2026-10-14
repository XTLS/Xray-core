package lua

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

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
		if tc.wantMessage != "" && !strings.Contains(err.Error(), tc.wantMessage) {
			t.Fatalf("Lua error = %v, want %q", err, tc.wantMessage)
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

func writeTestScript(t *testing.T, code string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "script.lua")
	if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
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
			L, err := program.NewState(context.Background(), nil, nil)
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
				L, err := program.NewState(context.Background(), nil, nil)
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
	L, err := program.NewState(context.Background(), nil, nil)
	if L != nil {
		L.Close()
		t.Fatal("failing signed script returned a state")
	}
	if err == nil || !strings.Contains(err.Error(), path+":5: signed failure") {
		t.Fatalf("signed initialization error = %v; want original source line 5", err)
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
    assert(package == nil)
    assert(require("_G") == _G)
    for _, name in ipairs({"io", "os", "debug", "channel", "dofile", "loadfile",
        "load", "loadstring", "getfenv", "setfenv", "collectgarbage", "module",
        "newproxy", "print", "_printregs"}) do
        assert(_G[name] == nil, name)
    end
    for _, name in ipairs({"io", "os", "debug", "channel", "package", "escape"}) do
        assert(not pcall(require, name), name)
    end
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
	L, err := program.NewState(context.Background(), func(L *glua.LState) {
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
	L, err := program.NewState(context.Background(), func(L *glua.LState) {
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
				L, err := program.NewState(context.Background(), func(L *glua.LState) {
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
	L, err := program.NewState(context.Background(), func(L *glua.LState) {
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

func TestProgramPrivilegedLibraries(t *testing.T) {
	setTestPrivilegedPublicKey(t, privilegedTestPublicKey)
	const body = `assert(require("io") == io and require("os") == os)
assert(require("debug") == debug and require("channel") == channel)
assert(type(coroutine.create) == "function" and require("coroutine") == coroutine)
assert(type(dofile) == "function" and type(loadfile) == "function")
assert(type(getfenv) == "function" and type(setfenv) == "function")
assert(type(collectgarbage) == "function" and type(print) == "function")
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
		{"base64", xbase64.Prefix + base64.StdEncoding.EncodeToString([]byte(code)), false},
		{"gzip", xbase64.GzipPrefix + base64.StdEncoding.EncodeToString(compressSource(t, code)), false},
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
