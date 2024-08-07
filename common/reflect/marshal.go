package reflect

import (
	"encoding/json"
	"reflect"
	"strings"

	cnet "github.com/xtls/xray-core/common/net"
	cserial "github.com/xtls/xray-core/common/serial"
)

func MarshalToJson(v interface{}, insertTypeInfo bool) (string, bool) {
	if itf := marshalInterface(v, true, insertTypeInfo); itf != nil {
		if b, err := json.MarshalIndent(itf, "", "  "); err == nil {
			return string(b[:]), true
		}
	}
	return "", false
}

func marshalTypedMessage(v *cserial.TypedMessage, ignoreNullValue bool, insertTypeInfo bool) interface{} {
	if v == nil {
		return nil
	}
	tmsg, err := v.GetInstance()
	if err != nil {
		return nil
	}
	r := marshalInterface(tmsg, ignoreNullValue, insertTypeInfo)
	if msg, ok := r.(map[string]interface{}); ok && insertTypeInfo {
		msg["_TypedMessage_"] = v.Type
	}
	return r
}

func marshalSlice(v reflect.Value, ignoreNullValue bool, insertTypeInfo bool) interface{} {
	r := make([]interface{}, 0)
	for i := 0; i < v.Len(); i++ {
		rv := v.Index(i)
		if rv.CanInterface() {
			value := rv.Interface()
			r = append(r, marshalInterface(value, ignoreNullValue, insertTypeInfo))
		}
	}
	return r
}

func isNullValue(f reflect.StructField, rv reflect.Value) bool {
	if rv.Kind() == reflect.String && rv.Len() == 0 {
		return true
	} else if !isValueKind(rv.Kind()) && rv.IsNil() {
		return true
	} else if tag := f.Tag.Get("json"); strings.Contains(tag, "omitempty") {
		if !rv.IsValid() || rv.IsZero() {
			return true
		}
	}
	return false
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
		} else {
			return tag
		}
	}
	return f.Name
}

func marshalStruct(v reflect.Value, ignoreNullValue bool, insertTypeInfo bool) interface{} {
	r := make(map[string]interface{})
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		rv := v.Field(i)
		if rv.CanInterface() {
			ft := t.Field(i)
			if !ignoreNullValue || !isNullValue(ft, rv) {
				name := toJsonName(ft)
				value := rv.Interface()
				tv := marshalInterface(value, ignoreNullValue, insertTypeInfo)
				r[name] = tv
			}
		}
	}
	return r
}

func marshalMap(v reflect.Value, ignoreNullValue bool, insertTypeInfo bool) interface{} {
	// policy.level is map[uint32] *struct
	kt := v.Type().Key()
	vt := reflect.TypeOf((*interface{})(nil))
	mt := reflect.MapOf(kt, vt)
	r := reflect.MakeMap(mt)
	for _, key := range v.MapKeys() {
		rv := v.MapIndex(key)
		if rv.CanInterface() {
			iv := rv.Interface()
			tv := marshalInterface(iv, ignoreNullValue, insertTypeInfo)
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

func marshalKnownType(v interface{}, ignoreNullValue bool, insertTypeInfo bool) (interface{}, bool) {
	switch ty := v.(type) {
	case cserial.TypedMessage:
		return marshalTypedMessage(&ty, ignoreNullValue, insertTypeInfo), true
	case *cserial.TypedMessage:
		return marshalTypedMessage(ty, ignoreNullValue, insertTypeInfo), true
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
	case cnet.Address:
		if d := v.(cnet.Address); d != nil {
			return d.String(), true
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

func marshalInterface(v interface{}, ignoreNullValue bool, insertTypeInfo bool) interface{} {

	if r, ok := marshalKnownType(v, ignoreNullValue, insertTypeInfo); ok {
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

	if ty := rv.Type().Name(); isValueKind(k) {
		if k.String() != ty {
			if s, ok := marshalIString(v); ok {
				return s
			}
		}
		return v
	}

	switch k {
	case reflect.Struct:
		return marshalStruct(rv, ignoreNullValue, insertTypeInfo)
	case reflect.Slice:
		return marshalSlice(rv, ignoreNullValue, insertTypeInfo)
	case reflect.Array:
		return marshalSlice(rv, ignoreNullValue, insertTypeInfo)
	case reflect.Map:
		return marshalMap(rv, ignoreNullValue, insertTypeInfo)
	default:
		break
	}

	if str, ok := marshalIString(v); ok {
		return str
	}
	return nil
}
