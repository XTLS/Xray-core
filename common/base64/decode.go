package base64

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

// Decode decodes Base64 text with an optional [Prefix] or [GzipPrefix].
func Decode(value string) ([]byte, error) {
	value, zip := strings.CutPrefix(value, GzipPrefix)
	if !zip {
		value = strings.TrimPrefix(value, Prefix)
	}

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("failed to decode base64").Base(err)
	}
	if !zip {
		return data, nil
	}

	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("failed to decompress gzip").Base(err)
	}
	defer reader.Close()
	data, err = io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("failed to decompress gzip").Base(err)
	}
	return data, nil
}
