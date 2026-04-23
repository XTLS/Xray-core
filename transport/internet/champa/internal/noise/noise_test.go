package noise

import (
	"bytes"
	"testing"
)

func TestReadKey(t *testing.T) {
	for _, test := range []struct {
		input  string
		output []byte
	}{
		{"", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []byte("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef")},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n", []byte("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef")},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nX", nil},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n\n", nil},
		{"\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil},
		{"X123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", nil},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil},
	} {
		output, err := ReadKey(bytes.NewReader([]byte(test.input)))
		if test.output == nil {
			if err == nil {
				t.Errorf("%+q expected error", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("%+q returned error %v", test.input, err)
			} else if !bytes.Equal(output, test.output) {
				t.Errorf("%+q got %x, expected %x", test.input, output, test.output)
			}
		}
	}
}
