package utils_test

import (
	"bytes"
	"net"
	"testing"

	. "github.com/xtls/xray-core/common/utils"
)

type accessInner struct {
	promoted int
}

type accessOuter struct {
	accessInner
	value   bytes.Buffer
	pointer *bytes.Buffer
}

func TestTryAccessField(t *testing.T) {
	obj := &accessOuter{}
	if TryAccessField[bytes.Buffer](obj, "value") != &obj.value || TryAccessField[*bytes.Buffer](obj, "pointer") != &obj.pointer {
		t.Error("a field is not where it is")
	}
	var conn net.Conn
	for name, found := range map[string]bool{
		"wrong type":               TryAccessField[bytes.Reader](obj, "value") != nil,
		"pointer instead of value": TryAccessField[bytes.Buffer](obj, "pointer") != nil,
		"promoted field":           TryAccessField[int](obj, "promoted") != nil,
		"missing field":            TryAccessField[int](obj, "missing") != nil,
		"non-pointer":              TryAccessField[bytes.Buffer](*obj, "value") != nil,
		"nil pointer":              TryAccessField[bytes.Buffer]((*accessOuter)(nil), "value") != nil,
		"nil":                      TryAccessField[int](nil, "value") != nil,
		"pointer to non-struct":    TryAccessField[int](new(int), "value") != nil,
		"nil interface":            TryAccessField[int](conn, "value") != nil,
	} {
		if found {
			t.Error(name, ": not nil")
		}
	}
}
