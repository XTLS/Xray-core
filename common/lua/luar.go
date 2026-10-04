package lua

import (
	glua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

// DirectMethod handles a Lua call without luar's reflected method invocation.
// It returns the result count and whether it handled the arguments. On false,
// it must leave the stack unchanged for the original luar wrapper.
type DirectMethod func(L *glua.LState) (nresults int, handled bool)

// PushWithDirectMethods pushes a luar userdata with typed Go method bindings.
// Handled calls bypass luar's argument conversion and reflect.Call; method lookup
// uses the methods table directly instead of luar's reflected __index handler.
// value must expose methods only. Bindings and their closures are installed once
// per Go type per LState, outside the method-call hot path.
func PushWithDirectMethods(L *glua.LState, value any, directMethods map[string]DirectMethod) {
	userdata := luar.New(L, value).(*glua.LUserData)
	metatable := userdata.Metatable.(*glua.LTable)
	methods := metatable.RawGetString("methods").(*glua.LTable)
	if metatable.RawGetString("__index") != methods {
		for name, direct := range directMethods {
			original := methods.RawGetString(name)
			fn := L.NewFunction(func(L *glua.LState) int {
				if nresults, handled := direct(L); handled {
					return nresults
				}
				return callLuarMethod(L, original)
			})
			// Keep luar's method aliases on the same direct binding.
			methods.ForEach(func(key, method glua.LValue) {
				if method == original {
					methods.RawSet(key, fn)
				}
			})
		}
		metatable.RawSetString("__index", methods)
	}
	L.Push(userdata)
}

func callLuarMethod(L *glua.LState, method glua.LValue) int {
	nargs := L.GetTop()
	L.Insert(method, 1)
	L.Call(nargs, glua.MultRet)
	return L.GetTop()
}
