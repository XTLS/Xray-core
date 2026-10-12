package base64

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestEncodeFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"bytes", []byte("你好\r\n\x00\xff")},
		{"multiple blocks", bytes.Repeat([]byte("local value = '你好'\n"), 8192)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, compress := range []bool{false, true} {
				prefix := Prefix
				if compress {
					prefix = ZstdPrefix
				}
				t.Run(prefix, func(t *testing.T) {
					value, err := Encode(tc.data, compress)
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
					if compress {
						if !bytes.HasPrefix(data, []byte{0x28, 0xb5, 0x2f, 0xfd}) {
							t.Fatal("compressed output is not a zstd frame")
						}
						reader, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
						if err != nil {
							t.Fatal(err)
						}
						defer reader.Close()
						data, err = reader.DecodeAll(data, nil)
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
