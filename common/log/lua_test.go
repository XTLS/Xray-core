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
	previous := logHandler.Load()
	t.Cleanup(func() { logHandler.Store(previous) })
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

type luaSeverityLogHandler struct {
	luaLogHandler
	level Severity
}

func (h *luaSeverityLogHandler) Severity() Severity { return h.level }

func TestLuaLogSeverity(t *testing.T) {
	previous := logHandler.Load()
	t.Cleanup(func() { logHandler.Store(previous) })
	L := lua.NewState()
	defer L.Close()
	RegisterLua(L)
	for _, level := range []Severity{Severity_Unknown, Severity_Error, Severity_Warning, Severity_Info, Severity_Debug, Severity_Warning} {
		t.Run(level.String(), func(t *testing.T) {
			handler := &luaSeverityLogHandler{level: level}
			RegisterHandler(handler)
			want := []Severity{}
			for _, severity := range []Severity{Severity_Error, Severity_Warning, Severity_Info, Severity_Debug} {
				if severity <= level {
					want = append(want, severity)
				}
			}
			if err := L.DoString(fmt.Sprintf(`
				local log = require("xray.log")
				local calls = 0
				local value = setmetatable({}, {
					__tostring = function() calls = calls + 1; return "message" end
				})
				for _, write in ipairs({log.Error, log.Warning, log.Info, log.Debug}) do
					assert(select("#", write(value)) == 0)
				end
				assert(calls == %d)
			`, len(want))); err != nil {
				t.Fatal(err)
			}
			if len(handler.messages) != len(want) {
				t.Fatalf("logged %d messages, want %d", len(handler.messages), len(want))
			}
			for i, severity := range want {
				msg := handler.messages[i].(*GeneralMessage)
				if msg.Severity != severity || msg.Content != "<string>: message" {
					t.Errorf("message %d = %v, want severity %v and content %q", i, msg, severity, "<string>: message")
				}
			}
		})
	}
}

type luaDiscardLogHandler struct{ level Severity }

func (luaDiscardLogHandler) Handle(Message)       {}
func (h luaDiscardLogHandler) Severity() Severity { return h.level }

func BenchmarkLuaLog(b *testing.B) {
	benchmarkLuaLog(b, Severity_Debug)
}

func BenchmarkLuaLogFiltered(b *testing.B) {
	benchmarkLuaLog(b, Severity_Warning)
}

func benchmarkLuaLog(b *testing.B, level Severity) {
	previous := logHandler.Load()
	b.Cleanup(func() { logHandler.Store(previous) })
	RegisterHandler(luaDiscardLogHandler{level: level})
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
