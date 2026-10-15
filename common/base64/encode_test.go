package base64

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestEncodeFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bytes", []byte("你好\r\n\x00\xff")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, zip := range []bool{false, true} {
				prefix := Prefix
				if zip {
					prefix = GzipPrefix
				}
				t.Run(prefix, func(t *testing.T) {
					value, err := Encode(tc.data, zip)
					if err != nil {
						t.Fatal(err)
					}
					payload, ok := strings.CutPrefix(value, prefix)
					if !ok {
						t.Fatalf("encoded value does not start with %q", prefix)
					}
					// Read the output independently of Decode so matching bugs cannot hide.
					data, err := base64.StdEncoding.DecodeString(payload)
					if err != nil {
						t.Fatal(err)
					}
					if zip {
						// gzip's XFL byte identifies the compression level we selected.
						if len(data) < 10 || data[8] != 2 {
							t.Fatal("gzip output does not use the highest compression level")
						}
						reader, err := gzip.NewReader(bytes.NewReader(data))
						if err != nil {
							t.Fatal(err)
						}
						defer reader.Close()
						data, err = io.ReadAll(reader)
						if err != nil {
							t.Fatal(err)
						}
					}
					if !bytes.Equal(data, tc.data) {
						t.Fatal("encoded output does not preserve the input bytes")
					}
				})
			}
		})
	}
}
