package splithttp

import (
	"bytes"
	"io"
	"testing"
)

type testWriteCloser struct{ io.Writer }

func (testWriteCloser) Close() error { return nil }

// TestDownlinkRoundTrip checks that the client-side reader reproduces exactly
// the bytes the server wrote, with keepalive frames (of various sizes) sprinkled
// in between and a single write large enough to span multiple data frames.
func TestDownlinkRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	dw := newDownlinkWriter(testWriteCloser{&wire})

	big := bytes.Repeat([]byte("A"), 3*downlinkMaxFramePayload+123) // spans 4 data frames
	writes := [][]byte{
		[]byte("hello world"),
		big,
		{}, // empty write must not emit a frame
		[]byte("tail"),
	}

	var want []byte
	for i, w := range writes {
		if _, err := dw.Write(w); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		want = append(want, w...)
		// idle==0 forces the keepalive to be emitted every time.
		if err := dw.keepAlive(0, []byte("keepalive-padding")); err != nil {
			t.Fatalf("keepalive %d: %v", i, err)
		}
	}
	if err := dw.keepAlive(0, nil); err != nil { // zero-length keepalive
		t.Fatal(err)
	}

	dr := newDownlinkReader(io.NopCloser(bytes.NewReader(wire.Bytes())))
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestDownlinkReaderByteAtATime exercises frame reassembly across arbitrary read
// boundaries by reading a single byte at a time.
func TestDownlinkReaderByteAtATime(t *testing.T) {
	var wire bytes.Buffer
	dw := newDownlinkWriter(testWriteCloser{&wire})
	if err := dw.keepAlive(0, []byte("pad")); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("xyz"), 5000)
	if _, err := dw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := dw.keepAlive(0, []byte("pad2")); err != nil {
		t.Fatal(err)
	}

	dr := newDownlinkReader(io.NopCloser(bytes.NewReader(wire.Bytes())))
	var got []byte
	one := make([]byte, 1)
	for {
		n, err := dr.Read(one)
		got = append(got, one[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("byte-at-a-time mismatch: got %d want %d", len(got), len(payload))
	}
}

// TestDownlinkReaderUnknownFrame ensures the reader rejects unknown frame types
// instead of silently corrupting the stream.
func TestDownlinkReaderUnknownFrame(t *testing.T) {
	wire := []byte{0x7f, 0x00, 0x01, 0x00} // type=0x7f, len=1, payload=0x00
	dr := newDownlinkReader(io.NopCloser(bytes.NewReader(wire)))
	if _, err := dr.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected error for unknown frame type, got nil")
	}
}

// TestDownlinkReaderCleanEOF ensures EOF exactly at a frame boundary surfaces as
// a clean io.EOF.
func TestDownlinkReaderCleanEOF(t *testing.T) {
	var wire bytes.Buffer
	dw := newDownlinkWriter(testWriteCloser{&wire})
	if _, err := dw.Write([]byte("done")); err != nil {
		t.Fatal(err)
	}
	dr := newDownlinkReader(io.NopCloser(bytes.NewReader(wire.Bytes())))
	buf := make([]byte, 4)
	n, err := dr.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(buf[:n]) != "done" {
		t.Fatalf("got %q, want %q", buf[:n], "done")
	}
	if _, err := dr.Read(buf); err != io.EOF {
		t.Fatalf("expected io.EOF at boundary, got %v", err)
	}
}
