package log

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

type luaLogHandler struct {
	messages []Message
}

func (h *luaLogHandler) Handle(msg Message) {
	h.messages = append(h.messages, msg)
}

func TestLuaLog(t *testing.T) {
	logHandler.RLock()
	previous := logHandler.Handler
	logHandler.RUnlock()
	t.Cleanup(func() { RegisterHandler(previous) })
	handler := &luaLogHandler{}
	RegisterHandler(handler)

	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	nativeError := L.NewUserData()
	nativeError.Value = fmt.Errorf("lookup failed: %w", errors.New("upstream timeout"))
	L.SetGlobal("nativeError", nativeError)
	path := filepath.Join(t.TempDir(), "logging.lua")
	if err := os.WriteFile(path, []byte(`
		local log = require("xray.log")
		assert(log == require("xray.log"))
		log.Debug("query: ", "example.com")
		log.Info("count=", 42, ", enabled=", true, ", value=", nil)
		log.Warning(setmetatable({}, {
			__tostring = function() return "fallback" end
		}))
		assert(select("#", log.Error("failed")) == 0)
		log.Error("DNS failed: ", nativeError)
		log.Warning(nativeError)
		local ok, err = pcall(function() error("Lua failure", 0) end)
		assert(not ok)
		log.Error(err)
		local calls = 0
		local custom = setmetatable({}, {
			__tostring = function() calls = calls + 1; return "custom" end
		})
		log.Info(custom, custom)
		assert(calls == 2)
		log.Info("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l")
		log.Info()
		function logHook()
			log.Info("hook")
		end
	`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := L.DoFile(path); err != nil {
		t.Fatal(err)
	}
	if err := L.DoString(`
		logHook()
		require("xray.log").Info("anonymous")
	`); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.lua")
	if err := os.WriteFile(other, []byte(`
		local log = require("xray.log")
		log.Info("other")
		logHook()
		log.Info("other again")
	`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := L.DoFile(other); err != nil {
		t.Fatal(err)
	}

	want := []struct {
		severity Severity
		message  string
	}{
		{Severity_Debug, "[Debug] logging.lua: query: example.com"},
		{Severity_Info, "[Info] logging.lua: count=42, enabled=true, value=nil"},
		{Severity_Warning, "[Warning] logging.lua: fallback"},
		{Severity_Error, "[Error] logging.lua: failed"},
		{Severity_Error, "[Error] logging.lua: DNS failed: lookup failed: upstream timeout"},
		{Severity_Warning, "[Warning] logging.lua: lookup failed: upstream timeout"},
		{Severity_Error, "[Error] logging.lua: Lua failure"},
		{Severity_Info, "[Info] logging.lua: customcustom"},
		{Severity_Info, "[Info] logging.lua: abcdefghijkl"},
		{Severity_Info, "[Info] logging.lua: "},
		{Severity_Info, "[Info] logging.lua: hook"},
		{Severity_Info, "[Info] <string>: anonymous"},
		{Severity_Info, "[Info] other.lua: other"},
		{Severity_Info, "[Info] logging.lua: hook"},
		{Severity_Info, "[Info] other.lua: other again"},
	}
	if len(handler.messages) != len(want) {
		t.Fatalf("logged %d messages, want %d", len(handler.messages), len(want))
	}
	for i, expected := range want {
		msg, ok := handler.messages[i].(*GeneralMessage)
		if !ok {
			t.Fatalf("message %d has type %T, want *GeneralMessage", i, handler.messages[i])
		}
		if msg.Severity != expected.severity || msg.String() != expected.message {
			t.Errorf("message %d = %q with severity %v, want %q with severity %v", i, msg.String(), msg.Severity, expected.message, expected.severity)
		}
	}
}

type luaDiscardLogHandler struct{}

func (luaDiscardLogHandler) Handle(Message) {}

func BenchmarkLuaLog(b *testing.B) {
	logHandler.RLock()
	previous := logHandler.Handler
	logHandler.RUnlock()
	b.Cleanup(func() { RegisterHandler(previous) })
	RegisterHandler(luaDiscardLogHandler{})
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	if err := L.DoString(`custom = setmetatable({}, {__tostring = function() return "custom" end})`); err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name, arguments string
	}{
		{"strings", `"query: ", "example.com"`},
		{"mixed", `"count=", 42, ", enabled=", true, ", value=", nil`},
		{"many_arguments", `"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"`},
		{"tostring", "custom"},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			if err := L.DoString(fmt.Sprintf(`local log = require("xray.log")
function benchmarkLog() log.Info(%s) end`, benchmark.arguments)); err != nil {
				b.Fatal(err)
			}
			fn := L.GetGlobal("benchmarkLog")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := L.CallByParam(lua.P{Fn: fn, NRet: 0, Protect: true}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
