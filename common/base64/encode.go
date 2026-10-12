package base64

import (
	"encoding/base64"

	"github.com/klauspost/compress/zstd"
	"github.com/xtls/xray-core/common/errors"
)

// Encode returns prefixed Base64 text, optionally compressed with zstd's highest available level.
func Encode(data []byte, compress bool) (string, error) {
	if !compress {
		return Prefix + base64.StdEncoding.EncodeToString(data), nil
	}

	writer, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(22)),
		zstd.WithEncoderConcurrency(1),
		zstd.WithZeroFrames(true),
	)
	if err != nil {
		return "", errors.New("failed to compress zstd").Base(err)
	}
	defer writer.Close()
	return ZstdPrefix + base64.StdEncoding.EncodeToString(writer.EncodeAll(data, nil)), nil
}
