package base64

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"

	"github.com/xtls/xray-core/common/errors"
)

// Encode returns prefixed Base64 text, optionally compressed with gzip at the highest level.
func Encode(data []byte, zip bool) (string, error) {
	if !zip {
		return Prefix + base64.StdEncoding.EncodeToString(data), nil
	}

	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	if _, err := writer.Write(data); err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	if err := writer.Close(); err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	return GzipPrefix + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
