package log

import (
	"path/filepath"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// RegisterLua makes xray.log available to require in an LState.
func RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.log", func(L *lua.LState) int {
		module := L.NewTable()
		for name, severity := range map[string]Severity{
			"debug":   Severity_Debug,
			"info":    Severity_Info,
			"warning": Severity_Warning,
			"error":   Severity_Error,
		} {
			module.RawSetString(name, L.NewFunction(func(L *lua.LState) int {
				var content strings.Builder
				// Prefix with the calling script's filename.
				if caller, ok := L.GetStack(1); ok {
					if _, err := L.GetInfo("S", caller, lua.LNil); err == nil && caller.Source != "" {
						content.WriteString(filepath.Base(strings.TrimPrefix(caller.Source, "@")))
						content.WriteString(": ")
					}
				}
				for i := 1; i <= L.GetTop(); i++ {
					value := L.Get(i)
					// Use Error() for Go errors in userdata.
					if ud, ok := value.(*lua.LUserData); ok {
						if err, ok := ud.Value.(error); ok {
							content.WriteString(err.Error())
							continue
						}
					}
					content.WriteString(L.ToStringMeta(value).String())
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
