package base64

import (
	"encoding/base64"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/xtls/xray-core/common/errors"
)

// Decode decodes Base64 text with an optional [Prefix] or [ZstdPrefix].
func Decode(value string) ([]byte, error) {
	value, compressed := strings.CutPrefix(value, ZstdPrefix)
	if !compressed {
		value = strings.TrimPrefix(value, Prefix)
	}

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("failed to decode base64").Base(err)
	}
	if !compressed {
		return data, nil
	}

	reader, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, errors.New("failed to decompress zstd").Base(err)
	}
	defer reader.Close()
	data, err = reader.DecodeAll(data, nil)
	if err != nil {
		return nil, errors.New("failed to decompress zstd").Base(err)
	}
	return data, nil
}
