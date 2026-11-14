// DO NOT EDIT. Regression test for app/geodata's luaGuardHeader.

package lua

import (
	"errors"
	"strings"
	"testing"

	"github.com/yuin/gopher-lua/parse"
)

func TestGeodataLuaGuard(t *testing.T) {
	_, err := parse.Parse(strings.NewReader("\x12\x01\x00function HandleRoute() end"), "geodata")
	var syntaxErr *parse.Error
	if !errors.As(err, &syntaxErr) || syntaxErr.Pos.Line != 1 || syntaxErr.Pos.Column != 1 {
		t.Fatalf("want Lua rejection at the first byte, got %v", err)
	}
}
