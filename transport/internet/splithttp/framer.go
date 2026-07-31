package splithttp

import (
	"bufio"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Stream-down framing (Variant 2).
//
// When both peers opt in (see the negotiation in dialer/client/hub), the
// stream-down response body is a sequence of length-prefixed records instead
// of a raw byte stream. This lets the server interleave keepalive records into
// an otherwise-silent download half (e.g. during a bulk upload) so a fronting
// CDN's idle read timeout never fires, without disturbing the tunnelled bytes.
//
// Wire format of one record:
//
//	record := uvarint(hdr) || payload
//	hdr    := (len << 1) | kind      // kind: 0 = data, 1 = padding(keepalive)
//
// A data record carries `len` bytes of tunnelled payload. A padding record
// carries `len` bytes of random filler that the reader discards; it exists only
// to produce traffic on the wire. Random (rather than zero) padding avoids a
// periodic 0x00 marker in the plaintext that an edge terminating TLS could key
// on.
const (
	frameKindData    = 0
	frameKindPadding = 1

	// maxFrameRecord bounds a single record's payload. A desync (old/new peer
	// mismatch, a middlebox mangling the body) then fails loudly here instead of
	// silently corrupting the tunnel.
	maxFrameRecord = 2 * 1024 * 1024 // 2 MiB

	// downFrameConfirmHeader is the response header the server sets to confirm
	// it framed the stream-down body. The client only strips framing after
	// seeing it, so an old (unframing) server is read as a raw stream.
	downFrameConfirmHeader = "X-Down-Frame"
)

// appendRecord appends one framed record (header + payload) to dst and returns
// the extended slice. It is the single encoder used by both data and padding
// paths so the wire format has exactly one source of truth.
func appendRecord(dst []byte, kind uint64, payload []byte) []byte {
	var hdr [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(hdr[:], (uint64(len(payload))<<1)|kind)
	dst = append(dst, hdr[:n]...)
	dst = append(dst, payload...)
	return dst
}

var framerBufPool = sync.Pool{
	New: func() any { return new([]byte) },
}

// downFramer wraps the server's stream-down writer (httpServerConn) and emits
// each Write as one data record. It also provides WritePadding for the
// keepalive goroutine. Both share a mutex so a keepalive record can never land
// in the middle of a data record, and each record is handed to the underlying
// writer in a single Write call.
//
// The single-Write invariant matters: httpServerConn.Write flushes on every
// call, so writing the header and payload separately would (a) let the
// keepalive goroutine interleave between them and (b) split one record across
// two HTTP/1.1 chunks. Framing the whole record into one buffer avoids both.
type downFramer struct {
	mu        sync.Mutex
	w         io.Writer
	lastWrite time.Time
}

func newDownFramer(w io.Writer) *downFramer {
	return &downFramer{w: w, lastWrite: time.Now()}
}

func (f *downFramer) writeRecord(kind uint64, payload []byte) error {
	bufPtr := framerBufPool.Get().(*[]byte)
	buf := (*bufPtr)[:0]
	buf = appendRecord(buf, kind, payload)
	_, err := f.w.Write(buf)
	*bufPtr = buf
	framerBufPool.Put(bufPtr)
	return err
}

// Write frames b as one or more data records. Payloads larger than
// maxFrameRecord are split so the reader's guard stays meaningful.
func (f *downFramer) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	total := 0
	for {
		chunk := b
		if len(chunk) > maxFrameRecord {
			chunk = chunk[:maxFrameRecord]
		}
		if err := f.writeRecord(frameKindData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		f.lastWrite = time.Now()
		b = b[len(chunk):]
		if len(b) == 0 {
			break
		}
	}
	return total, nil
}

// WritePadding emits a keepalive record only if the connection has been idle
// (no data record) for at least idle. It returns whether a record was written
// and any write error, so the caller's timer can back off while real data is
// flowing.
func (f *downFramer) WritePadding(idle time.Duration, payload []byte) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if time.Since(f.lastWrite) < idle {
		return false, nil
	}
	if len(payload) > maxFrameRecord {
		payload = payload[:maxFrameRecord]
	}
	if err := f.writeRecord(frameKindPadding, payload); err != nil {
		return false, err
	}
	return true, nil
}

// Close forwards to the underlying writer when it is closable.
func (f *downFramer) Close() error {
	if c, ok := f.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// framedReader strips stream-down framing on the client. It parses records off
// the underlying reader, discards padding, and returns data payloads. A record
// is consumed across as many Read calls as needed; the remainder is kept
// between calls.
type framedReader struct {
	br        *bufio.Reader
	closer    io.Closer
	remaining int // unread bytes of the current data record
}

func newFramedReader(rc io.ReadCloser) *framedReader {
	return &framedReader{
		br:     bufio.NewReader(rc),
		closer: rc,
	}
}

func (r *framedReader) Read(p []byte) (int, error) {
	// Advance to the next data record with unread payload, skipping padding
	// and empty data records.
	for r.remaining == 0 {
		hdr, err := binary.ReadUvarint(r.br)
		if err != nil {
			return 0, err
		}
		length := int(hdr >> 1)
		kind := hdr & 1
		if length < 0 || length > maxFrameRecord {
			return 0, errors.New("splithttp: stream-down record too large: ", length)
		}
		if kind == frameKindPadding {
			if _, err := io.CopyN(io.Discard, r.br, int64(length)); err != nil {
				// A short read mid-record is a desync, not a clean end.
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			continue
		}
		r.remaining = length
	}

	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	read, err := r.br.Read(p[:n])
	r.remaining -= read
	// The underlying stream ended in the middle of a data record's payload.
	if err == io.EOF && r.remaining > 0 {
		err = io.ErrUnexpectedEOF
	}
	return read, err
}

func (r *framedReader) Close() error {
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}
