package splithttp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// nopWriteCloser adapts a bytes.Buffer to io.WriteCloser.
type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

func framedReaderFromBytes(b []byte) *framedReader {
	return newFramedReader(io.NopCloser(bytes.NewReader(b)))
}

// Test_Framer_RoundTrip writes several data payloads through the server framer
// and reads them back through the client stripper; the concatenated output must
// equal the concatenated input, and no framing bytes may leak.
func Test_Framer_RoundTrip(t *testing.T) {
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})

	payloads := [][]byte{
		[]byte("hello"),
		[]byte(""), // empty data record must be tolerated
		bytes.Repeat([]byte{0xAB}, 5000),
		[]byte("tail"),
	}
	var want bytes.Buffer
	for _, p := range payloads {
		if _, err := fw.Write(p); err != nil {
			t.Fatalf("Write: %v", err)
		}
		want.Write(p)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), want.Len())
	}
}

// Test_Framer_SkipsPadding ensures keepalive (padding) records are transparent
// to the reader: interleaving them between data records changes nothing on the
// application stream.
func Test_Framer_SkipsPadding(t *testing.T) {
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})

	if _, err := fw.Write([]byte("AAA")); err != nil {
		t.Fatal(err)
	}
	// Force a padding record regardless of idle time by using idle=0.
	if ok, err := fw.WritePadding(0, bytes.Repeat([]byte{'X'}, 128)); err != nil || !ok {
		t.Fatalf("WritePadding ok=%v err=%v", ok, err)
	}
	if _, err := fw.Write([]byte("BBB")); err != nil {
		t.Fatal(err)
	}
	if ok, err := fw.WritePadding(0, nil); err != nil || !ok {
		t.Fatalf("empty WritePadding ok=%v err=%v", ok, err)
	}
	if _, err := fw.Write([]byte("CCC")); err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "AAABBBCCC" {
		t.Fatalf("padding leaked into stream: %q", got)
	}
}

// Test_Framer_PaddingRespectsIdle checks WritePadding is a no-op while data is
// flowing (idle window not elapsed) and fires once the writer has been quiet.
func Test_Framer_PaddingRespectsIdle(t *testing.T) {
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})
	if _, err := fw.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := fw.WritePadding(time.Hour, []byte("X")); ok {
		t.Fatal("padding written while within idle window")
	}
	if ok, err := fw.WritePadding(0, []byte("X")); err != nil || !ok {
		t.Fatalf("padding not written after idle elapsed: ok=%v err=%v", ok, err)
	}
}

// Test_Framer_PartialReads verifies a single large data record is delivered
// correctly across many small Read calls, with the remainder carried between
// calls.
func Test_Framer_PartialReads(t *testing.T) {
	payload := make([]byte, 40000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}

	fr := framedReaderFromBytes(wire.Bytes())
	var got bytes.Buffer
	small := make([]byte, 7)
	for {
		n, err := fr.Read(small)
		got.Write(small[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("partial read mismatch: got %d want %d", got.Len(), len(payload))
	}
}

// Test_Framer_LargePayloadSplit ensures a data payload larger than
// maxFrameRecord is split into multiple records on the wire (each within the
// guard) yet reassembles byte-for-byte.
func Test_Framer_LargePayloadSplit(t *testing.T) {
	payload := make([]byte, maxFrameRecord+1234)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}

	// Inspect the wire: the first record's declared length must respect the
	// guard.
	firstHdr, err := binary.ReadUvarint(bytes.NewReader(wire.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if int(firstHdr>>1) > maxFrameRecord {
		t.Fatalf("first record %d exceeds guard %d", firstHdr>>1, maxFrameRecord)
	}

	got, err := io.ReadAll(framedReaderFromBytes(wire.Bytes()))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("large payload mismatch: got %d want %d", len(got), len(payload))
	}
}

// Test_Framer_MaxRecordGuard proves a corrupt/oversized length prefix fails
// loudly instead of being silently accepted.
func Test_Framer_MaxRecordGuard(t *testing.T) {
	var hdr [binary.MaxVarintLen64]byte
	// Declare a data record far larger than the guard, with no payload.
	n := binary.PutUvarint(hdr[:], uint64(maxFrameRecord+1)<<1)

	_, err := io.ReadAll(framedReaderFromBytes(hdr[:n]))
	if err == nil {
		t.Fatal("expected error on oversized record, got nil")
	}
}

// Test_Framer_TruncatedRecord ensures a record whose payload is cut short
// surfaces an error rather than silently returning partial data as complete.
func Test_Framer_TruncatedRecord(t *testing.T) {
	var wire bytes.Buffer
	fw := newDownFramer(nopWriteCloser{&wire})
	if _, err := fw.Write(bytes.Repeat([]byte{'Z'}, 1000)); err != nil {
		t.Fatal(err)
	}
	truncated := wire.Bytes()[:len(wire.Bytes())-100] // drop 100 payload bytes

	_, err := io.ReadAll(framedReaderFromBytes(truncated))
	if err == nil {
		t.Fatal("expected error on truncated record, got nil")
	}
}
