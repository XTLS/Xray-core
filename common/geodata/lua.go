package geodata

import (
	lua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

// RegisterLua makes xray.geodata available to require in an LState.
func RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.geodata", func(L *lua.LState) int {
		module := L.NewTable()

		module.RawSetString("BuildDomainMatcher", L.NewFunction(func(L *lua.LState) int {
			parsed, err := ParseDomainRules(luaRules(L), Domain_Domain)
			if err != nil {
				L.RaiseError("%v", err)
				return 0
			}
			matcher, err := DomainReg.BuildDomainMatcher(parsed)
			if err != nil {
				L.RaiseError("%v", err)
				return 0
			}
			L.Push(luar.New(L, matcher))
			return 1
		}))

		module.RawSetString("BuildIPMatcher", L.NewFunction(func(L *lua.LState) int {
			parsed, err := ParseIPRules(luaRules(L))
			if err != nil {
				L.RaiseError("%v", err)
				return 0
			}
			matcher, err := IPReg.BuildIPMatcher(parsed)
			if err != nil {
				L.RaiseError("%v", err)
				return 0
			}
			L.Push(luar.New(L, matcher))
			return 1
		}))
		L.Push(module)
		return 1
	})
}

func luaRules(L *lua.LState) []string {
	rules := make([]string, L.GetTop())
	for i := range rules {
		value, ok := L.Get(i + 1).(lua.LString)
		if !ok {
			L.RaiseError("geodata rules must be strings")
			return nil
		}
		rules[i] = string(value)
	}
	return rules
}
