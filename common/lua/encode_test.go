package lua

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	glua "github.com/yuin/gopher-lua"
)

func TestEncodeRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
	}{
		{"empty", nil},
		{"padding", []byte("x")},
		{"unicode", []byte(`value = "你好"`)},
		{"multiline", []byte("-- comment\r\nvalue = 42\n")},
		{"binary", []byte{0, 0xff, 0xfe, 1, 2}},
		{"large", bytes.Repeat([]byte("-- repeated code\n"), 32768)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, zip := range []bool{false, true} {
				prefix := "base64:"
				if zip {
					prefix = "base64+gzip:"
				}
				t.Run(prefix, func(t *testing.T) {
					script, err := Encode(tc.code, zip)
					if err != nil {
						t.Fatal(err)
					}
					encoded, ok := strings.CutPrefix(script, prefix)
					if !ok {
						t.Fatalf("encoded script does not start with %q", prefix)
					}
					code, err := decode(encoded, zip)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(code, tc.code) {
						t.Fatal("decoded bytes differ from input")
					}
				})
			}
		})
	}
}

func TestEncodeBestCompression(t *testing.T) {
	script, err := Encode([]byte("value = 42"), true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(script, "base64+gzip:"))
	if err != nil {
		t.Fatal(err)
	}
	// The gzip XFL header byte is 2 for the highest compression level.
	if len(data) < 10 || data[8] != 2 {
		t.Fatal("gzip header does not indicate highest compression")
	}
}

func TestEncodeCompile(t *testing.T) {
	for _, zip := range []bool{false, true} {
		script, err := Encode([]byte(`value = "你好"`), zip)
		if err != nil {
			t.Fatal(err)
		}
		program, err := Compile(script)
		if err != nil {
			t.Fatal(err)
		}
		state, err := program.NewState(context.Background(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := state.GetGlobal("value"); got != glua.LString("你好") {
			state.Close()
			t.Fatalf("value = %v, want 你好", got)
		}
		state.Close()
	}
}
