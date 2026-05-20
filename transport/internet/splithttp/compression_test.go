package splithttp

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func TestCompressionZstdRoundTrip(t *testing.T) {
	config := &Config{Compression: &CompressionConfig{Type: "zstd", CompressLevel: 3}}
	payload := bytes.Repeat([]byte("xhttp-zstd-payload-"), 4096)

	compressed, err := compressPayload(config, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(compressed) >= len(payload) {
		t.Fatalf("expected compressed payload to be smaller than %d, got %d", len(payload), len(compressed))
	}

	decompressed, err := decompressPayload(config, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatal("decompressed payload differs from original")
	}
}

func TestCompressionLz4RoundTrip(t *testing.T) {
	config := &Config{Compression: &CompressionConfig{Type: "lz4", CompressLevel: 1}}
	payload := bytes.Repeat([]byte("xhttp-lz4-payload-"), 4096)

	compressed, err := compressPayload(config, payload)
	if err != nil {
		t.Fatal(err)
	}
	decompressed, err := decompressPayload(config, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatal("decompressed payload differs from original")
	}
}

func TestCompressionDisabledIsNoop(t *testing.T) {
	payload := []byte("plain payload")

	compressed, err := compressPayload(&Config{}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compressed, payload) {
		t.Fatalf("disabled compression changed payload: %q", compressed)
	}

	decompressed, err := decompressPayload(&Config{}, compressed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatalf("disabled decompression changed payload: %q", decompressed)
	}
}

func TestCompressionRejectsUnknownType(t *testing.T) {
	config := &Config{Compression: &CompressionConfig{Type: "br"}}

	if _, err := compressPayload(config, []byte("payload")); err == nil {
		t.Fatal("expected unknown compression type error")
	}
	if _, err := decompressPayload(config, []byte("payload")); err == nil {
		t.Fatal("expected unknown compression type error")
	}
}

func TestPacketCompressionCompressesBodyPayload(t *testing.T) {
	config := &Config{
		UplinkDataPlacement: PlacementBody,
		Compression: &CompressionConfig{
			Type:          "zstd",
			CompressLevel: 3,
		},
	}
	payload := bytes.Repeat([]byte("xhttp-body-payload-"), 4096)
	request, err := http.NewRequest("POST", "http://example.com/upload", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = config.FillPacketRequest(request, "session", "0", buf.MultiBuffer{buf.FromBytes(payload)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) >= len(payload) {
		t.Fatalf("expected compressed body to be smaller than %d, got %d", len(payload), len(body))
	}
	decompressed, err := decompressPayload(config, body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decompressed, payload) {
		t.Fatal("decompressed request body differs from original")
	}
	if request.ContentLength != int64(len(body)) {
		t.Fatalf("unexpected content length: %d, want %d", request.ContentLength, len(body))
	}
}

func TestStreamCompressionFramesPayload(t *testing.T) {
	config := &Config{Compression: &CompressionConfig{Type: "zstd", CompressLevel: 3}}
	payload := bytes.Repeat([]byte("xhttp-stream-payload-"), 4096)
	raw := &bytesWriteCloser{}
	writer := newCompressedWriteCloser(config, raw)

	n, err := writer.Write(payload)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("unexpected written bytes: %d, want %d", n, len(payload))
	}
	if raw.Len() >= len(payload) {
		t.Fatalf("expected framed compressed stream to be smaller than %d, got %d", len(payload), raw.Len())
	}

	reader := newCompressedReadCloser(config, io.NopCloser(bytes.NewReader(raw.Bytes())))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("decoded stream differs from original")
	}
}

type bytesWriteCloser struct {
	bytes.Buffer
}

func (w *bytesWriteCloser) Close() error {
	return nil
}
