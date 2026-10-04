package log

import (
	"path/filepath"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// RegisterLua makes xray.log available to require in an LState.
func RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.log", func(L *lua.LState) int {
		module := L.CreateTable(0, 4)
		var source, prefix string // cache
		for name, severity := range map[string]Severity{
			"Debug":   Severity_Debug,
			"Info":    Severity_Info,
			"Warning": Severity_Warning,
			"Error":   Severity_Error,
		} {
			module.RawSetString(name, L.NewFunction(func(L *lua.LState) int {
				if GetSeverity() < severity {
					return 0
				}
				var content strings.Builder
				// Prefix with the calling script's filename.
				if caller, ok := L.GetStack(1); ok {
					if _, err := L.GetInfo("S", caller, lua.LNil); err == nil && caller.Source != "" {
						if caller.Source != source {
							source = caller.Source
							prefix = filepath.Base(strings.TrimPrefix(source, "@")) + ": "
						}
						content.WriteString(prefix)
					}
				}
				for i := 1; i <= L.GetTop(); i++ {
					content.WriteString(luaLogString(L, L.Get(i)))
				}
				Record(&GeneralMessage{
					Severity: severity,
					Content:  content.String(),
				})
				return 0
			}))
		}
		L.Push(module)
		return 1
	})
}

func luaLogString(L *lua.LState, value lua.LValue) string {
	if ud, ok := value.(*lua.LUserData); ok {
		if err, ok := ud.Value.(error); ok {
			return err.Error()
		}
	}
	if _, ok := L.GetMetaField(value, "__tostring").(*lua.LFunction); ok {
		return L.ToStringMeta(value).String()
	}
	return value.String()
}
