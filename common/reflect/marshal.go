package reflect

import (
	"encoding/json"
	"reflect"
	"strings"

	cnet "github.com/xtls/xray-core/common/net"
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

func isNullValue(v interface{}) bool {
	if v == nil {
		return true
	}
	kind := reflect.TypeOf(v).Kind()
	switch kind {
	case reflect.Slice, reflect.Array, reflect.Map, reflect.Struct:
		return reflect.ValueOf(v).Len() == 0
	default:
		return false
	}
}

func toJsonName(f reflect.StructField) string {
	if tags := f.Tag.Get("protobuf"); len(tags) > 0 {
		for _, tag := range strings.Split(tags, ",") {
			if before, after, ok := strings.Cut(tag, "="); ok && before == "json" {
				return after
			}
		}
	}
	if tag := f.Tag.Get("json"); len(tag) > 0 {
		if before, _, ok := strings.Cut(tag, ","); ok {
			return before
		}
	}
	return f.Name
}

func marshalStruct(v reflect.Value, ignoreNullValue bool) interface{} {
	r := make(map[string]interface{})
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		rv := v.Field(i)
		if rv.CanInterface() {
			ft := t.Field(i)
			name := toJsonName(ft)
			value := rv.Interface()
			tv := marshalInterface(value, ignoreNullValue)
			if !ignoreNullValue || !isNullValue(tv) {
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
	case *json.RawMessage, json.RawMessage:
		return ty, true
	case *cnet.IPOrDomain:
		if d := v.(*cnet.IPOrDomain); d != nil {
			return d.AsAddress().String(), true
		}
		return nil, false
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
		if ty := rv.Type().Name(); k.String() != ty {
			if s, ok := marshalIString(v); ok {
				return s
			}
		}
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
