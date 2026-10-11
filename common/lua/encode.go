package lua

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"

	"github.com/xtls/xray-core/common/errors"
)

// Encode returns an inline script, optionally compressed with gzip at the highest level.
func Encode(code []byte, zip bool) (string, error) {
	if !zip {
		return "base64:" + base64.StdEncoding.EncodeToString(code), nil
	}

	var data bytes.Buffer
	writer, err := gzip.NewWriterLevel(&data, gzip.BestCompression)
	if err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	if _, err := writer.Write(code); err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	if err := writer.Close(); err != nil {
		return "", errors.New("failed to compress gzip").Base(err)
	}
	return "base64+gzip:" + base64.StdEncoding.EncodeToString(data.Bytes()), nil
}
