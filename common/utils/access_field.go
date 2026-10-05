package utils

import (
	"reflect"
	"unsafe"
)

// AccessField can used to access unexported field of a struct
// valueType must be the exact type of the field or it will panic
func AccessField[valueType any](obj any, fieldName string) *valueType {
	field := reflect.ValueOf(obj).Elem().FieldByName(fieldName)
	if field.Type() != reflect.TypeOf(*new(valueType)) {
		panic("field type: " + field.Type().String() + ", valueType: " + reflect.TypeOf(*new(valueType)).String())
	}
	v := (*valueType)(unsafe.Pointer(field.UnsafeAddr()))
	return v
}

// TryAccessField is AccessField that returns nil if obj has no such field of that type.
func TryAccessField[valueType any](obj any, fieldName string) *valueType {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil
	}
	field, ok := v.Elem().Type().FieldByName(fieldName)
	if !ok || len(field.Index) != 1 || field.Type != reflect.TypeFor[valueType]() {
		return nil
	}
	return (*valueType)(unsafe.Add(v.UnsafePointer(), field.Offset))
}
