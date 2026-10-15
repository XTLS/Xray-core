package lua

import (
	"net"
	"reflect"

	glua "github.com/yuin/gopher-lua"
	luar "layeh.com/gopher-luar"
)

// NewSlicePusher captures luar's slice metatable during state initialization.
// The returned function wraps slices without reflection or metatable lookup,
// and pushes nil for nil slices. Use it with this state or its coroutines.
func NewSlicePusher[T any](L *glua.LState) func(*glua.LState, []T) {
	metatable := luar.MT(L, []T(nil)).LTable
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

// NewReadOnlySlicePusher borrows slices without copying and recursively makes
// nested slice types read-only through their shared metatables. IP byte views
// and masks are also read-only. Other referenced elements retain their mutability.
// Element bindings are initialized on first indexing or iteration.
func NewReadOnlySlicePusher[T any](L *glua.LState) func(*glua.LState, []T) {
	sliceMetatable := luar.MT(L, []T{})
	if sliceMetatable.RawGetString("__readonly") != glua.LTrue {
		readOnly := L.NewFunction(func(L *glua.LState) int {
			L.RaiseError("slice is read-only")
			return 0
		})
		setSliceReadOnly[[]T](L, readOnly)
	}
	return NewSlicePusher[T](L)
}

func setSliceReadOnly[S ~[]E, E any](L *glua.LState, readOnly *glua.LFunction) {
	var visit func(reflect.Type)
	visit = func(typ reflect.Type) {
		if typ.Kind() != reflect.Slice {
			return
		}
		metatable := luar.MT(L, reflect.Zero(typ).Interface())
		if metatable.RawGetString("__readonly") == glua.LTrue {
			return
		}
		// Mark before descending because named slice types can be recursive.
		metatable.RawSetString("__readonly", glua.LTrue)
		metatable.RawSetString("__newindex", readOnly)
		// Reject explicitly so Lua cannot fall back to the other operand.
		metatable.RawSetString("__add", readOnly)
		if typ == reflect.TypeFor[net.IP]() {
			// A nil receiver lets AppendText return its argument as a writable []byte.
			methods := metatable.RawGetString("methods").(*glua.LTable)
			appendText := methods.RawGetString("AppendText")
			for key, method := methods.Next(glua.LNil); key != glua.LNil; key, method = methods.Next(key) {
				if method == appendText {
					methods.RawSet(key, glua.LNil)
				}
			}
			visit(reflect.TypeFor[net.IPMask]())
		}
		if element := typ.Elem(); element.Kind() == reflect.Slice {
			index := metatable.RawGetString("__index").(*glua.LFunction)
			call := metatable.RawGetString("__call").(*glua.LFunction)
			initialize := func() {
				visit(element)
				metatable.RawSetString("__index", index)
				metatable.RawSetString("__call", call)
			}
			metatable.RawSetString("__index", L.NewFunction(func(L *glua.LState) int {
				initialize()
				return index.GFunction(L)
			}))
			metatable.RawSetString("__call", L.NewFunction(func(L *glua.LState) int {
				initialize()
				return call.GFunction(L)
			}))
		}
	}
	visit(reflect.TypeFor[S]())
}

// DirectMethod handles a Lua call without luar's reflected method invocation.
// It returns the result count and whether it handled the arguments. On false,
// it must leave the stack unchanged for the original luar wrapper.
type DirectMethod func(L *glua.LState) (nresults int, handled bool)

// PushMethods pushes a luar userdata exposing only the named Go methods and
// their aliases through reflected calls. The method list is fixed by the first
// binding of that Go type in each LState.
func PushMethods(L *glua.LState, value any, methods ...string) {
	PushWithDirectMethods(L, value, nil, methods...)
}

// PushWithDirectMethods pushes a luar userdata with typed Go method bindings.
// Handled calls bypass luar's argument conversion and reflect.Call; method lookup
// uses the methods table directly instead of luar's reflected __index handler.
// Only directMethods and additionalMethods are exposed, including their aliases.
// Bindings and their closures are installed once per Go type per LState, outside
// the method-call hot path.
func PushWithDirectMethods(L *glua.LState, value any, directMethods map[string]DirectMethod, additionalMethods ...string) {
	userdata := luar.New(L, value).(*glua.LUserData)
	metatable := userdata.Metatable.(*glua.LTable)
	methods := metatable.RawGetString("methods").(*glua.LTable)
	if metatable.RawGetString("__index") != methods {
		// Keep all aliases for the explicitly exposed methods.
		exposed := make(map[glua.LValue]bool, len(directMethods)+len(additionalMethods))
		for name := range directMethods {
			exposed[methods.RawGetString(name)] = true
		}
		for _, name := range additionalMethods {
			exposed[methods.RawGetString(name)] = true
		}
		for key, method := methods.Next(glua.LNil); key != glua.LNil; key, method = methods.Next(key) {
			if !exposed[method] {
				methods.RawSet(key, glua.LNil)
			}
		}
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
		// Pointer operations would bypass the method-only API.
		metatable.RawSetString("__newindex", glua.LNil)
		metatable.RawSetString("__pow", glua.LNil)
		metatable.RawSetString("__unm", glua.LNil)
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
