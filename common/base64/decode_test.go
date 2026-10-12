package base64

import (
	"bytes"
	"testing"
)

func TestDecodeFormats(t *testing.T) {
	compressed, err := Encode([]byte("x"), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value, want string
	}{
		{"unprefixed", "eA==", "x"},
		{"base64", Prefix + "eA==", "x"},
		{"gzip", compressed, "x"},
		{"empty", Prefix, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := Decode(tc.value)
			if err != nil || !bytes.Equal(data, []byte(tc.want)) {
				t.Fatalf("Decode = %q, %v; want %q", data, err, tc.want)
			}
		})
	}
}
