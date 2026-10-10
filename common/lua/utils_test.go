package lua

import (
	"errors"
	"math"
	"strings"
	"testing"

	glua "github.com/yuin/gopher-lua"
)

func TestReadUint32(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   glua.LValue
		want    uint32
		wantErr bool
	}{
		{name: "zero", value: glua.LNumber(0)},
		{name: "integer", value: glua.LNumber(45), want: 45},
		{name: "maximum", value: glua.LNumber(math.MaxUint32), want: math.MaxUint32},
		{name: "fraction", value: glua.LNumber(1.5), wantErr: true},
		{name: "negative", value: glua.LNumber(-1), wantErr: true},
		{name: "overflow", value: glua.LNumber(math.MaxUint32 + 1), wantErr: true},
		{name: "NaN", value: glua.LNumber(math.NaN()), wantErr: true},
		{name: "positive infinity", value: glua.LNumber(math.Inf(1)), wantErr: true},
		{name: "negative infinity", value: glua.LNumber(math.Inf(-1)), wantErr: true},
		{name: "nil", value: glua.LNil, wantErr: true},
		{name: "numeric string", value: glua.LString("45"), wantErr: true},
		{name: "boolean", value: glua.LTrue, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadUint32(tc.value, "invalid number")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("ReadUint32() = %d, %v; want %d, error %t", got, err, tc.want, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid number") {
				t.Fatalf("error = %v, want invalid number", err)
			}
		})
	}
}

func TestReadOptionalString(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   glua.LValue
		want    string
		wantErr bool
	}{
		{name: "nil", value: glua.LNil},
		{name: "empty", value: glua.LString("")},
		{name: "string", value: glua.LString("out"), want: "out"},
		{name: "number", value: glua.LNumber(1), wantErr: true},
		{name: "boolean", value: glua.LFalse, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadOptionalString(tc.value, "invalid string")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("ReadOptionalString() = %q, %v; want %q, error %t", got, err, tc.want, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "invalid string") {
				t.Fatalf("error = %v, want invalid string", err)
			}
		})
	}
}

func TestUserDataRoundTrip(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	want := []int{1, 2}
	PushUserData(L, want)
	if L.GetTop() != 1 {
		t.Fatalf("stack top = %d, want 1", L.GetTop())
	}
	got, err := ReadUserData[[]int](L.Get(-1), "invalid userdata")
	if err != nil || len(got) != len(want) || &got[0] != &want[0] {
		t.Fatalf("userdata = %v, %v; want original slice", got, err)
	}
	PushUserData(L, []int(nil))
	if got, err := ReadUserData[[]int](L.Get(-1), "invalid userdata"); err != nil || got != nil {
		t.Fatalf("nil slice userdata = %v, %v", got, err)
	}
	for _, value := range []glua.LValue{glua.LNil, glua.LString("1"), L.NewTable(), L.Get(1)} {
		if got, err := ReadUserData[int](value, "invalid userdata"); got != 0 || err == nil || !strings.Contains(err.Error(), "invalid userdata") {
			t.Fatalf("ReadUserData(%v) = %d, %v; want invalid userdata", value, got, err)
		}
	}
}

func TestErrorRoundTrip(t *testing.T) {
	L := glua.NewState()
	defer L.Close()
	want := errors.New("upstream failed")
	for _, err := range []error{nil, want} {
		PushError(L, err)
		if L.GetTop() != 1 {
			t.Fatalf("stack top = %d, want 1", L.GetTop())
		}
		if err == nil && L.Get(-1) != glua.LNil {
			t.Fatalf("nil error pushed as %v", L.Get(-1))
		}
		if got := ReadError(L.Get(-1), "invalid error"); got != err {
			t.Fatalf("ReadError() = %v, want original error %v", got, err)
		}
		L.Pop(1)
	}
	for _, message := range []string{"script failed", ""} {
		if err := ReadError(glua.LString(message), "invalid error"); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("string error = %v, want %q", err, message)
		}
	}
	wrong := L.NewUserData()
	wrong.Value = "not a native error"
	for _, value := range []glua.LValue{glua.LTrue, glua.LNumber(1), L.NewTable(), wrong, L.NewUserData()} {
		if err := ReadError(value, "invalid error"); err == nil || !strings.Contains(err.Error(), "invalid error") {
			t.Fatalf("ReadError(%v) = %v, want invalid error", value, err)
		}
	}
}
