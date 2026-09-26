package log

import (
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// RegisterLua makes xray.log available to require in an LState.
// Logging functions concatenate arguments using Lua's tostring semantics,
// except Go errors in userdata use Error(). Messages go through the current
// log handler.
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
				for i := 1; i <= L.GetTop(); i++ {
					value := L.Get(i)
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
