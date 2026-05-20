package splithttp

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/xtls/xray-core/common/errors"
)

const (
	compressionNone = "none"
	compressionZstd = "zstd"
	compressionLz4  = "lz4"
)

func normalizedCompressionType(config *Config) string {
	if config == nil || config.Compression == nil || config.Compression.Type == "" {
		return compressionNone
	}
	return config.Compression.Type
}

func compressionEnabled(config *Config) bool {
	return normalizedCompressionType(config) != compressionNone
}

func compressPayload(config *Config, payload []byte) ([]byte, error) {
	switch normalizedCompressionType(config) {
	case compressionNone:
		return payload, nil
	case compressionZstd:
		options := []zstd.EOption{zstd.WithEncoderConcurrency(1)}
		if config.Compression.CompressLevel != 0 {
			options = append(options, zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(int(config.Compression.CompressLevel))))
		}
		encoder, err := zstd.NewWriter(nil, options...)
		if err != nil {
			return nil, err
		}
		defer encoder.Close()
		return encoder.EncodeAll(payload, nil), nil
	case compressionLz4:
		var out bytes.Buffer
		writer := lz4.NewWriter(&out)
		level, err := lz4CompressionLevel(config.Compression.CompressLevel)
		if err != nil {
			return nil, err
		}
		if err := writer.Apply(lz4.CompressionLevelOption(level)); err != nil {
			return nil, err
		}
		if _, err := writer.Write(payload); err != nil {
			return nil, err
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	default:
		return nil, errors.New("unsupported compression type: " + config.Compression.Type)
	}
}

func decompressPayload(config *Config, payload []byte) ([]byte, error) {
	switch normalizedCompressionType(config) {
	case compressionNone:
		return payload, nil
	case compressionZstd:
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		return decoder.DecodeAll(payload, nil)
	case compressionLz4:
		var out bytes.Buffer
		if _, err := io.Copy(&out, lz4.NewReader(bytes.NewReader(payload))); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	default:
		return nil, errors.New("unsupported compression type: " + config.Compression.Type)
	}
}

type compressedWriteCloser struct {
	io.WriteCloser
	config *Config
	mu     sync.Mutex
}

func newCompressedWriteCloser(config *Config, writer io.WriteCloser) io.WriteCloser {
	if !compressionEnabled(config) {
		return writer
	}
	return &compressedWriteCloser{
		WriteCloser: writer,
		config:      config,
	}
}

func (w *compressedWriteCloser) Write(payload []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	compressed, err := compressPayload(w.config, payload)
	if err != nil {
		return 0, err
	}
	if uint64(len(compressed)) > uint64(^uint32(0)) {
		return 0, errors.New("compressed frame is too large: ", len(compressed))
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(compressed)))
	if err := writeFull(w.WriteCloser, header[:]); err != nil {
		return 0, err
	}
	if err := writeFull(w.WriteCloser, compressed); err != nil {
		return 0, err
	}
	return len(payload), nil
}

type compressedReadCloser struct {
	io.ReadCloser
	config  *Config
	pending []byte
}

func newCompressedReadCloser(config *Config, reader io.ReadCloser) io.ReadCloser {
	if !compressionEnabled(config) {
		return reader
	}
	return &compressedReadCloser{
		ReadCloser: reader,
		config:     config,
	}
}

func (r *compressedReadCloser) Read(payload []byte) (int, error) {
	for len(r.pending) == 0 {
		var header [4]byte
		if _, err := io.ReadFull(r.ReadCloser, header[:]); err != nil {
			return 0, err
		}
		frameLen := binary.BigEndian.Uint32(header[:])
		if frameLen == 0 {
			continue
		}
		frame := make([]byte, frameLen)
		if _, err := io.ReadFull(r.ReadCloser, frame); err != nil {
			return 0, err
		}
		decompressed, err := decompressPayload(r.config, frame)
		if err != nil {
			return 0, err
		}
		r.pending = decompressed
	}

	n := copy(payload, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func lz4CompressionLevel(level int32) (lz4.CompressionLevel, error) {
	switch level {
	case 0:
		return lz4.Fast, nil
	case 1:
		return lz4.Level1, nil
	case 2:
		return lz4.Level2, nil
	case 3:
		return lz4.Level3, nil
	case 4:
		return lz4.Level4, nil
	case 5:
		return lz4.Level5, nil
	case 6:
		return lz4.Level6, nil
	case 7:
		return lz4.Level7, nil
	case 8:
		return lz4.Level8, nil
	case 9:
		return lz4.Level9, nil
	default:
		if level < 0 {
			return lz4.Fast, nil
		}
		return lz4.Fast, errors.New("unsupported lz4 compressLevel: ", level)
	}
}
