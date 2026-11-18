package xmc

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func plainFrame(body []byte) []byte {
	frame := make([]byte, 0, 5+len(body))
	length := Varint(len(body))
	var buf bytes.Buffer
	_ = length.writeTo(&buf)
	frame = append(frame, buf.Bytes()...)
	return append(frame, body...)
}

type wireFrame struct {
	packetLength int
	dataLength   int
	payload      []byte
}

func readWireFrame(t *testing.T, r *bytes.Reader) wireFrame {
	t.Helper()
	packetLength, _, err := readVarintWithLength(r)
	if err != nil {
		t.Fatalf("read packet length: %v", err)
	}
	dataLength, dataLengthSize, err := readVarintWithLength(r)
	if err != nil {
		t.Fatalf("read data length: %v", err)
	}
	payload := make([]byte, int(packetLength)-dataLengthSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return wireFrame{packetLength: int(packetLength), dataLength: int(dataLength), payload: payload}
}

func randomBody(t *testing.T, size int) []byte {
	t.Helper()
	body := make([]byte, size)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("random body: %v", err)
	}
	return body
}

// TestCompressionWriterNeverCompresses pins the write policy: whatever the
// negotiated threshold is, XMC sends the uncompressed framing so that a padding
// turn keeps its wire size. A padded turn of zeros would otherwise deflate from
// tens of kilobytes to a hundred bytes and the shape would be gone.
func TestCompressionWriterNeverCompresses(t *testing.T) {
	for _, size := range []int{1, 10, 255, 256, 257, 32768, 65535, 65536} {
		for _, body := range [][]byte{bytes.Repeat([]byte{0}, size), randomBody(t, size)} {
			var wire bytes.Buffer
			w := newCompressionWriter(&wire)
			if _, err := w.Write(plainFrame(body)); err != nil {
				t.Fatalf("size %d: write: %v", size, err)
			}

			frame := readWireFrame(t, bytes.NewReader(wire.Bytes()))
			if frame.dataLength != 0 {
				t.Fatalf("size %d: writer compressed the body (data length %d)", size, frame.dataLength)
			}
			if !bytes.Equal(frame.payload, body) {
				t.Fatalf("size %d: payload mismatch", size)
			}
			if frame.packetLength != 1+size {
				t.Fatalf("size %d: packet length %d, want %d", size, frame.packetLength, 1+size)
			}
			if wire.Len() != varintSize(Varint(1+size))+1+size {
				t.Fatalf("size %d: frame is %d bytes on the wire, want %d", size, wire.Len(), varintSize(Varint(1+size))+1+size)
			}

			decoded, _, err := readFrame(newCompressionReader(bytes.NewReader(wire.Bytes())), maxUncompressedFrameBody)
			if err != nil {
				t.Fatalf("size %d: decode: %v", size, err)
			}
			if !bytes.Equal(decoded, body) {
				t.Fatalf("size %d: round trip mismatch", size)
			}
		}
	}
}

func TestCompressionRoundTripChunked(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		randomBody(t, 255),
		randomBody(t, 24*1024),
		randomBody(t, 64*1024),
		bytes.Repeat([]byte("xmc"), 8*1024),
	}

	var wire bytes.Buffer
	w := newCompressionWriter(&wire)
	// One Write per frame, split into awkward chunk sizes.
	for _, body := range cases {
		frame := plainFrame(body)
		for len(frame) > 0 {
			n := 7
			if n > len(frame) {
				n = len(frame)
			}
			if _, err := w.Write(frame[:n]); err != nil {
				t.Fatalf("chunked write: %v", err)
			}
			frame = frame[n:]
		}
	}

	r := newCompressionReader(bytes.NewReader(wire.Bytes()))
	for i, want := range cases {
		got, _, err := readFrame(r, maxUncompressedFrameBody)
		if err != nil {
			t.Fatalf("frame %d: decode: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: mismatch (%d vs %d bytes)", i, len(got), len(want))
		}
	}
	if _, _, err := readFrame(r, maxUncompressedFrameBody); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after the last frame, got %v", err)
	}
}

func TestCompressionMultipleFramesOneWrite(t *testing.T) {
	var plain []byte
	bodies := [][]byte{[]byte("a"), randomBody(t, 1024), randomBody(t, 300)}
	for _, body := range bodies {
		plain = append(plain, plainFrame(body)...)
	}

	var wire bytes.Buffer
	w := newCompressionWriter(&wire)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := newCompressionReader(bytes.NewReader(wire.Bytes()))
	for i, want := range bodies {
		got, _, err := readFrame(r, maxUncompressedFrameBody)
		if err != nil {
			t.Fatalf("frame %d: decode: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: mismatch", i)
		}
	}
}

// Vanilla servers accept uncompressed packets even when the body exceeds the
// negotiated threshold, which is what lets padding frames keep their wire size.
func TestCompressionReaderUncompressedOverThreshold(t *testing.T) {
	body := randomBody(t, 64*1024)
	var wire bytes.Buffer
	length := Varint(1 + len(body))
	if err := length.writeTo(&wire); err != nil {
		t.Fatal(err)
	}
	wire.WriteByte(0)
	wire.Write(body)

	got, _, err := readFrame(newCompressionReader(bytes.NewReader(wire.Bytes())), maxUncompressedFrameBody)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("payload mismatch")
	}
}

// The writer stopped compressing, but a real server still does, so the reader
// must keep decoding deflated bodies.
func TestCompressionReaderDecodesCompressedBody(t *testing.T) {
	body := append(bytes.Repeat([]byte("xmc"), 4096), 0, 1, 2, 3)

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	var wire bytes.Buffer
	packetLength := Varint(varintSize(Varint(len(body))) + compressed.Len())
	if err := packetLength.writeTo(&wire); err != nil {
		t.Fatal(err)
	}
	dataLength := Varint(len(body))
	if err := dataLength.writeTo(&wire); err != nil {
		t.Fatal(err)
	}
	wire.Write(compressed.Bytes())

	got, _, err := readFrame(newCompressionReader(bytes.NewReader(wire.Bytes())), maxUncompressedFrameBody)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatal("payload mismatch")
	}
}

func TestCompressionReaderErrors(t *testing.T) {
	// Compressed packet with a bogus body.
	var badZlib bytes.Buffer
	length := Varint(1 + 10)
	_ = length.writeTo(&badZlib)
	dataLength := Varint(64)
	_ = dataLength.writeTo(&badZlib)
	badZlib.Write(bytes.Repeat([]byte{0xff}, 10))
	if _, _, err := readFrame(newCompressionReader(bytes.NewReader(badZlib.Bytes())), maxUncompressedFrameBody); err == nil {
		t.Fatal("expected an error for an invalid zlib body")
	}

	// Uncompressed length beyond the vanilla limit.
	var tooLong bytes.Buffer
	length = Varint(1 + 4)
	_ = length.writeTo(&tooLong)
	dataLength = Varint(maxUncompressedFrameBody + 1)
	_ = dataLength.writeTo(&tooLong)
	tooLong.Write([]byte{1, 2, 3, 4})
	if _, _, err := readFrame(newCompressionReader(bytes.NewReader(tooLong.Bytes())), maxUncompressedFrameBody); err == nil {
		t.Fatal("expected an error for an oversized uncompressed length")
	}

	// Truncated payload.
	var truncated bytes.Buffer
	length = Varint(1 + 100)
	_ = length.writeTo(&truncated)
	var zero Varint
	_ = zero.writeTo(&truncated)
	truncated.Write([]byte{1, 2, 3})
	if _, _, err := readFrame(newCompressionReader(bytes.NewReader(truncated.Bytes())), maxUncompressedFrameBody); err == nil {
		t.Fatal("expected an error for a truncated payload")
	}
}

func TestCompressionWriterInvalidFrameLength(t *testing.T) {
	var wire bytes.Buffer
	w := newCompressionWriter(&wire)
	if _, err := w.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("expected an error for an invalid frame length prefix")
	}
}
