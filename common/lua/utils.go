package lua

import (
	"math"

	"github.com/xtls/xray-core/common/errors"
	glua "github.com/yuin/gopher-lua"
)

type number interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr |
		~float32 | ~float64
}

// PushNumber converts a Go number to a Lua number and pushes it.
func PushNumber[T number](L *glua.LState, value T) {
	L.Push(glua.LNumber(value))
}

// PushString converts a Go string to a Lua string and pushes it.
func PushString(L *glua.LState, value string) {
	L.Push(glua.LString(value))
}

// PushNil pushes Lua nil.
func PushNil(L *glua.LState) {
	L.Push(glua.LNil)
}

// PushUserData pushes a native Go value without copying it.
func PushUserData(L *glua.LState, value any) {
	ud := L.NewUserData()
	ud.Value = value
	L.Push(ud)
}

// PushError pushes nil or the original Go error as userdata.
func PushError(L *glua.LState, err error) {
	if err == nil {
		L.Push(glua.LNil)
		return
	}
	PushUserData(L, err)
}

// ReadUserData reads a native Go value of type T without copying it.
// Other Lua values or userdata containing a different type return invalidMessage.
func ReadUserData[T any](value glua.LValue, invalidMessage string) (T, error) {
	if ud, ok := value.(*glua.LUserData); ok {
		if result, ok := ud.Value.(T); ok {
			return result, nil
		}
	}
	var zero T
	return zero, errors.New(invalidMessage)
}

// ReadError accepts nil, a native Go error, or a Lua string.
// Native errors retain their identity; other values return invalidMessage.
func ReadError(value glua.LValue, invalidMessage string) error {
	if value == glua.LNil {
		return nil
	}
	if ud, ok := value.(*glua.LUserData); ok {
		if err, ok := ud.Value.(error); ok {
			return err
		}
	}
	if message, ok := value.(glua.LString); ok {
		return errors.New(string(message))
	}
	return errors.New(invalidMessage)
}

// ReadUint32 accepts only integral Lua numbers in the uint32 range.
func ReadUint32(value glua.LValue, invalidMessage string) (uint32, error) {
	number, ok := value.(glua.LNumber)
	if !ok || number < 0 || number > math.MaxUint32 || math.Trunc(float64(number)) != float64(number) {
		return 0, errors.New(invalidMessage)
	}
	return uint32(number), nil
}

// ReadOptionalString accepts a Lua string or nil, which becomes an empty string.
// It does not coerce other values to strings.
func ReadOptionalString(value glua.LValue, invalidMessage string) (string, error) {
	if value == glua.LNil {
		return "", nil
	}
	if result, ok := value.(glua.LString); ok {
		return string(result), nil
	}
	return "", errors.New(invalidMessage)
}
