package geodata

import (
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/common/net"
	lua "github.com/yuin/gopher-lua"
)

// RegisterLua makes xray.geodata available to require in an LState.
func RegisterLua(L *lua.LState) {
	L.PreloadModule("xray.geodata", func(L *lua.LState) int {
		module := L.CreateTable(0, 2)

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
			xlua.PushWithDirectMethods(L, matcher, map[string]xlua.DirectMethod{
				"Match":    newLuaDomainMatch(xlua.NewSlicePusher[uint32](L)),
				"MatchAny": luaDomainMatchAny,
			})
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
			xlua.PushWithDirectMethods(L, matcher, map[string]xlua.DirectMethod{
				"Match":     luaIPMatch,
				"AnyMatch":  luaIPAnyMatch,
				"Matches":   luaIPMatches,
				"FilterIPs": newLuaIPFilterIPs(xlua.NewSlicePusher[net.IP](L)),
			})
			return 1
		}))

		L.Push(module)
		return 1
	})
}

// Read native Go values by type assertion; slices keep their original storage.
func readLuaIPMatcherArgs[T any](L *lua.LState) (IPMatcher, T, bool) {
	var input T
	if L.GetTop() != 2 {
		return nil, input, false
	}
	value, ok := L.Get(1).(*lua.LUserData)
	if !ok {
		return nil, input, false
	}
	matcher, ok := value.Value.(IPMatcher)
	if !ok {
		return nil, input, false
	}
	if L.Get(2) == lua.LNil {
		return matcher, input, true
	}
	value, ok = L.Get(2).(*lua.LUserData)
	if !ok {
		return nil, input, false
	}
	input, ok = value.Value.(T)
	return matcher, input, ok
}

func luaIPMatch(L *lua.LState) (int, bool) {
	matcher, ip, ok := readLuaIPMatcherArgs[net.IP](L)
	if !ok {
		return 0, false
	}
	L.Push(lua.LBool(matcher.Match(ip)))
	return 1, true
}

func luaIPAnyMatch(L *lua.LState) (int, bool) {
	matcher, ips, ok := readLuaIPMatcherArgs[[]net.IP](L)
	if !ok {
		return 0, false
	}
	L.Push(lua.LBool(matcher.AnyMatch(ips)))
	return 1, true
}

func luaIPMatches(L *lua.LState) (int, bool) {
	matcher, ips, ok := readLuaIPMatcherArgs[[]net.IP](L)
	if !ok {
		return 0, false
	}
	L.Push(lua.LBool(matcher.Matches(ips)))
	return 1, true
}

func newLuaIPFilterIPs(pushIPs func(*lua.LState, []net.IP)) xlua.DirectMethod {
	return func(L *lua.LState) (int, bool) {
		matcher, ips, ok := readLuaIPMatcherArgs[[]net.IP](L)
		if !ok {
			return 0, false
		}
		matched, unmatched := matcher.FilterIPs(ips)
		pushIPs(L, matched)
		pushIPs(L, unmatched)
		return 2, true
	}
}

func newLuaDomainMatch(pushMatches func(*lua.LState, []uint32)) xlua.DirectMethod {
	return func(L *lua.LState) (int, bool) {
		if L.GetTop() == 2 {
			if value, ok := L.Get(1).(*lua.LUserData); ok {
				matcher, validMatcher := value.Value.(DomainMatcher)
				domain, validDomain := L.Get(2).(lua.LString)
				if validMatcher && validDomain {
					pushMatches(L, matcher.Match(string(domain)))
					return 1, true
				}
			}
		}
		return 0, false
	}
}

func luaDomainMatchAny(L *lua.LState) (int, bool) {
	if L.GetTop() == 2 {
		if value, ok := L.Get(1).(*lua.LUserData); ok {
			matcher, validMatcher := value.Value.(DomainMatcher)
			domain, validDomain := L.Get(2).(lua.LString)
			if validMatcher && validDomain {
				L.Push(lua.LBool(matcher.MatchAny(string(domain))))
				return 1, true
			}
		}
	}
	return 0, false
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
