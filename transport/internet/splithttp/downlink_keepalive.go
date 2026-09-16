package splithttp

import (
	"bufio"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"strconv"
	"time"
)

// Downlink keepalive and buffer-flush padding.
//
// Some CDNs reset a response stream when the origin sends nothing for a fixed
// time (30s is common), even while the client is still uploading. Others hold
// back the tail of a response -- whatever's sitting in an internal buffer
// page -- until either more data arrives or the response ends; since a
// packet-up downlink never "ends" (it's a long-lived session stream, not one
// bounded response), a buffered tail can sit there until an unrelated timeout
// finally kills the connection. The downlink is a raw byte stream, so the
// server cannot inject filler into it on its own; the client has to know
// which bytes are real.
//
// Both sides are opt-in via scDownlinkKeepAliveHeader, a header name that's empty
// (i.e. the feature is off) unless explicitly configured -- there's no
// built-in default, so an existing deployment that upgrades the binary
// without touching its config keeps behaving exactly as it did before this
// feature existed. When configured, the client sends that header with its
// requested scDownlinkKeepAliveSecs interval on the request that carries
// the downlink. A server that's configured with the same header name
// answers with it too and switches the response body to framed mode: every
// write is prefixed with a length, and the low bit of that length says
// what kind of frame it is:
//
//	length = 2*n      -- a real frame of n bytes: this is what a real write
//	                     always looks like.
//	length = 2*n + 1   -- a padding frame of n bytes, written by the server
//	                     to keep the connection alive and, when idle-flush is
//	                     configured, to force a buffering intermediary to
//	                     flush; the client reads and discards the n bytes
//	                     whole and never surfaces them. n == 0 is the cheap
//	                     periodic keepalive ping -- there's only one filler
//	                     frame type, whether it's carrying zero bytes or a
//	                     CDN-busting payload.
//
// There is no separate marker byte or reserved sentinel value -- "is this
// padding" rides on the length field that was already there to say how much
// data follows, and the value is a genuine byte count either way, not a
// magic constant. A passive observer sees only ordinary variable-length
// frames. See runDownlinkPacer for when padding actually gets written.
//
// The client only unframes the body if the response carries the header, so
// either side can be an unpatched build.

// requestedDownlinkKeepAlive returns the interval the client asked for, or
// 0. The caller (hub.go) only calls this once the server has opted in to
// downlink keepalive at all -- there's no cap here on the value itself; the
// server has no way to know what idle-timeout the client's own network path
// needs to beat, so it honors whatever the client asks for as-is.
func requestedDownlinkKeepAlive(value string) time.Duration {
	if value == "" {
		return 0
	}
	secs, err := strconv.Atoi(value)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// writeFrameHeader writes the length prefix for a frame of n bytes; padding
// selects which of the two frame kinds described above it is.
func writeFrameHeader(w io.Writer, n int, padding bool) (int, error) {
	var hdr [binary.MaxVarintLen64]byte
	length := uint64(n) << 1
	if padding {
		length |= 1
	}
	hn := binary.PutUvarint(hdr[:], length)
	return w.Write(hdr[:hn])
}

// writeFramed writes b as a single real frame -- same shape as the plain
// unframed Write() it replaces, just with a length prefix in front. The
// caller holds the conn lock.
func writeFramed(w io.Writer, b []byte) (int, error) {
	if _, err := writeFrameHeader(w, len(b), false); err != nil {
		return 0, err
	}
	return w.Write(b)
}

// genPaddingBytes fills b with non-repeating, non-special-looking filler.
// Content doesn't need to be cryptographically random -- it only needs to
// not look like a fixed marker -- so math/rand/v2 is fine here, same as the
// rest of this package's padding generation (see xpadding.go).
func genPaddingBytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < len(b); i += 8 {
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], rand.Uint64())
		copy(b[i:], word[:])
	}
	return b
}

type framedReader struct {
	r    *bufio.Reader
	body io.Closer
	left uint64
}

func newFramedReader(body io.ReadCloser) io.ReadCloser {
	return &framedReader{r: bufio.NewReaderSize(body, 32*1024), body: body}
}

func (f *framedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for f.left == 0 {
		raw, err := binary.ReadUvarint(f.r)
		if err != nil {
			return 0, err
		}
		size := raw >> 1
		if size == 0 {
			continue // empty frame (real or padding) -- no-op, read the next one
		}
		if raw&1 != 0 {
			// padding: consume and discard whole, never surfaced to the caller
			if _, err := io.CopyN(io.Discard, f.r, int64(size)); err != nil {
				return 0, err
			}
			continue
		}
		f.left = size
	}
	if uint64(len(p)) > f.left {
		p = p[:f.left]
	}
	n, err := f.r.Read(p)
	f.left -= uint64(n)
	if err == io.EOF && f.left > 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (f *framedReader) Close() error {
	return f.body.Close()
}
