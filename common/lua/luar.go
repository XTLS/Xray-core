package lua

import (
	glua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

// NewSlicePusher captures luar's slice metatable during state initialization.
// The returned function wraps slices without reflection or metatable lookup,
// and pushes nil for nil slices. Use it with this state or its coroutines.
func NewSlicePusher[T any](L *glua.LState) func(*glua.LState, []T) {
	metatable := luar.New(L, []T{}).(*glua.LUserData).Metatable
	return func(L *glua.LState, values []T) {
		if values == nil {
			L.Push(glua.LNil)
			return
		}
		userdata := L.NewUserData()
		userdata.Value = values
		userdata.Metatable = metatable
		L.Push(userdata)
	}
}

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
			for key, method := methods.Next(glua.LNil); key != glua.LNil; key, method = methods.Next(key) {
				if method == original {
					methods.RawSet(key, fn)
				}
			}
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
