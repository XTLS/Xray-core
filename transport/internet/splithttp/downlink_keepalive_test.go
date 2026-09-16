package splithttp

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

type nopCloser struct{ io.Reader }

func (nopCloser) Close() error { return nil }

func TestDownlinkFramingRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	var want bytes.Buffer
	for i, size := range []int{1, 0, 127, 128, 16383, 16384, 1 << 20, 3} {
		if i%2 == 0 {
			writeFrameHeader(&wire, 0, true) // 0-byte padding (keepalive ping) between real writes
		}
		b := make([]byte, size)
		rand.Read(b)
		want.Write(b)
		n, err := writeFramed(&wire, b)
		if err != nil || n != size {
			t.Fatalf("writeFramed(%d) = %d, %v", size, n, err)
		}
	}
	writeFrameHeader(&wire, 0, true)
	writeFrameHeader(&wire, 0, true)

	r := newFramedReader(nopCloser{&wire})
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), want.Len())
	}
}

func TestDownlinkFramingPaddingIsDiscarded(t *testing.T) {
	var wire bytes.Buffer
	writeFramed(&wire, []byte("hello"))
	writeFrameHeader(&wire, 9000, true) // large padding frame between real data
	wire.Write(genPaddingBytes(9000))
	writeFramed(&wire, []byte("world"))
	// a padding frame with the SAME numeric magnitude as a real frame elsewhere,
	// to make sure it's the parity bit that matters, not the value
	writeFrameHeader(&wire, 5, true)
	wire.Write([]byte("XXXXX"))
	writeFramed(&wire, []byte("!"))

	r := newFramedReader(nopCloser{&wire})
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helloworld!" {
		t.Fatalf("padding leaked into stream: got %q", got)
	}
}

func TestDownlinkFramingSmallReads(t *testing.T) {
	var wire bytes.Buffer
	writeFramed(&wire, []byte("hello"))
	writeFrameHeader(&wire, 4, true)
	wire.Write([]byte("PADD"))
	writeFramed(&wire, []byte("world"))
	r := newFramedReader(nopCloser{&wire})
	var out []byte
	p := make([]byte, 2)
	for {
		n, err := r.Read(p)
		out = append(out, p[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(out) != "helloworld" {
		t.Fatalf("got %q", out)
	}
}

func TestDownlinkFramingErrors(t *testing.T) {
	var wire bytes.Buffer
	writeFramed(&wire, []byte("truncated"))
	trunc := wire.Bytes()[:wire.Len()-3]
	if _, err := io.ReadAll(newFramedReader(nopCloser{bytes.NewReader(trunc)})); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated frame: err = %v", err)
	}
}

func TestRequestedDownlinkKeepAlive(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 0, "0": 0, "-5": 0, "abc": 0, "15": 15 * time.Second, "999999": 999999 * time.Second,
	} {
		if got := requestedDownlinkKeepAlive(in); got != want {
			t.Errorf("requestedDownlinkKeepAlive(%q) = %v, want %v", in, got, want)
		}
	}
}
