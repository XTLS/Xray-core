package reflect

import (
	"encoding/json"
	"reflect"

	cserial "github.com/xtls/xray-core/common/serial"
)

func MarshalToJson(v interface{}) (string, bool) {
	if itf := marshalInterface(v, true); itf != nil {
		if b, err := json.MarshalIndent(itf, "", "  "); err == nil {
			return string(b[:]), true
		}
	}
	return "", false
}

func marshalTypedMessage(v *cserial.TypedMessage, ignoreNullValue bool) interface{} {
	if v == nil {
		return nil
	}
	tmsg, err := v.GetInstance()
	if err != nil {
		return nil
	}
	r := marshalInterface(tmsg, ignoreNullValue)
	if msg, ok := r.(map[string]interface{}); ok {
		msg["_TypedMessage_"] = v.Type
	}
	return r
}

func marshalSlice(v reflect.Value, ignoreNullValue bool) interface{} {
	r := make([]interface{}, 0)
	for i := 0; i < v.Len(); i++ {
		rv := v.Index(i)
		if rv.CanInterface() {
			value := rv.Interface()
			r = append(r, marshalInterface(value, ignoreNullValue))
		}
	}
	return r
}

func marshalStruct(v reflect.Value, ignoreNullValue bool) interface{} {
	r := make(map[string]interface{})
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		rv := v.Field(i)
		if rv.CanInterface() {
			ft := t.Field(i)
			name := ft.Name
			value := rv.Interface()
			tv := marshalInterface(value, ignoreNullValue)
			if tv != nil || !ignoreNullValue {
				r[name] = tv
			}
		}
	}
	return r
}

func marshalMap(v reflect.Value, ignoreNullValue bool) interface{} {
	// policy.level is map[uint32] *struct
	kt := v.Type().Key()
	vt := reflect.TypeOf((*interface{})(nil))
	mt := reflect.MapOf(kt, vt)
	r := reflect.MakeMap(mt)
	for _, key := range v.MapKeys() {
		rv := v.MapIndex(key)
		if rv.CanInterface() {
			iv := rv.Interface()
			tv := marshalInterface(iv, ignoreNullValue)
			if tv != nil || !ignoreNullValue {
				r.SetMapIndex(key, reflect.ValueOf(&tv))
			}
		}
	}
	return r.Interface()
}

func marshalIString(v interface{}) (r string, ok bool) {
	defer func() {
		if err := recover(); err != nil {
			r = ""
			ok = false
		}
	}()

	if iStringFn, ok := v.(interface{ String() string }); ok {
		return iStringFn.String(), true
	}
	return "", false
}

func marshalKnownType(v interface{}, ignoreNullValue bool) (interface{}, bool) {
	switch ty := v.(type) {
	case cserial.TypedMessage:
		return marshalTypedMessage(&ty, ignoreNullValue), true
	case *cserial.TypedMessage:
		return marshalTypedMessage(ty, ignoreNullValue), true
	case map[string]json.RawMessage:
		return ty, true
	case []json.RawMessage:
		return ty, true
	case *json.RawMessage:
		return ty, true
	case json.RawMessage:
		return ty, true
	default:
		return nil, false
	}
}

func isValueKind(kind reflect.Kind) bool {
	switch kind {
	case reflect.Bool,
		reflect.Int,
		reflect.Int8,
		reflect.Int16,
		reflect.Int32,
		reflect.Int64,
		reflect.Uint,
		reflect.Uint8,
		reflect.Uint16,
		reflect.Uint32,
		reflect.Uint64,
		reflect.Uintptr,
		reflect.Float32,
		reflect.Float64,
		reflect.Complex64,
		reflect.Complex128,
		reflect.String:
		return true
	default:
		return false
	}
}

func marshalInterface(v interface{}, ignoreNullValue bool) interface{} {

	if r, ok := marshalKnownType(v, ignoreNullValue); ok {
		return r
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	k := rv.Kind()
	if k == reflect.Invalid {
		return nil
	}
	if isValueKind(k) {
		return v
	}

	switch k {
	case reflect.Struct:
		return marshalStruct(rv, ignoreNullValue)
	case reflect.Slice:
		return marshalSlice(rv, ignoreNullValue)
	case reflect.Array:
		return marshalSlice(rv, ignoreNullValue)
	case reflect.Map:
		return marshalMap(rv, ignoreNullValue)
	default:
		break
	}

	if str, ok := marshalIString(v); ok {
		return str
	}
	return nil
}
