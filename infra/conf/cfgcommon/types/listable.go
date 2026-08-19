package types

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
)

// Listable allows a field to be unmarshalled from a single object or a list of objects.
// If the json input is a single object, it will be stored as a slice with one element.
// If the json input is null or empty or a single empty object, it will be nil.
type Listable[T any] []T

func (l *Listable[T]) UnmarshalJSON(data []byte) error {
	var v T
	if len(data) != 0 && !slices.Equal(data, []byte("null")) && data[0] != '[' {
		if err := json.Unmarshal(data, &v); err == nil {
			// make the list nil if the single value is the zero value
			var zero T
			if reflect.DeepEqual(v, zero) {
				return nil
			}
			*l = []T{v}
			return err
		}
	}
	return json.Unmarshal(data, (*[]T)(l))
}

// ListableSimpleString is like Listable[string], but able to separate by `~`
type ListableSimpleString []string

func (l *ListableSimpleString) UnmarshalJSON(data []byte) error {
	var v string
	if len(data) != 0 && !slices.Equal(data, []byte("null")) && data[0] != '[' {
		if err := json.Unmarshal(data, &v); err == nil {
			if v == "" {
				// make the list nil if the single value is empty string
				return nil
			}
			*l = strings.Split(v, "~")
			return nil
		}
	}
	return json.Unmarshal(data, (*[]string)(l))
}
