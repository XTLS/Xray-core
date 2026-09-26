package log

import (
	"errors"
	"fmt"
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
	if err := L.DoString(`
		local log = require("xray.log")
		assert(log == require("xray.log"))
		log.debug("query: ", "example.com")
		log.info("count=", 42, ", enabled=", true, ", value=", nil)
		log.warning(setmetatable({}, {
			__tostring = function() return "fallback" end
		}))
		assert(select("#", log.error("failed")) == 0)
		log.error("DNS failed: ", nativeError)
		log.warning(nativeError)
		local ok, err = pcall(function() error("Lua failure", 0) end)
		assert(not ok)
		log.error(err)
	`); err != nil {
		t.Fatal(err)
	}

	want := []struct {
		severity Severity
		message  string
	}{
		{Severity_Debug, "[Debug] query: example.com"},
		{Severity_Info, "[Info] count=42, enabled=true, value=nil"},
		{Severity_Warning, "[Warning] fallback"},
		{Severity_Error, "[Error] failed"},
		{Severity_Error, "[Error] DNS failed: lookup failed: upstream timeout"},
		{Severity_Warning, "[Warning] lookup failed: upstream timeout"},
		{Severity_Error, "[Error] Lua failure"},
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
