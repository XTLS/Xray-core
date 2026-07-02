package splithttp

import (
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Downlink wrapping format (opt-in, enabled by scStreamDownServerSecs).
//
// When enabled, the server wraps the XHTTP server->client ("download") byte
// stream into a minimal length-prefixed frame format, and the client unwraps
// it. This gives the download stream an in-band keepalive, so an idle download
// response is not cut off by buffering / inactivity-timeout intermediaries
// (e.g. CDNs that only hold an idle HTTP response open for a limited time).
// See XTLS/Xray-core#4846.
//
// Every frame is:
//
//	+--------+-----------------+==========================+
//	| type   | length (uint16) | payload (length bytes)   |
//	| 1 byte | big-endian      |                          |
//	+--------+-----------------+==========================+
//
// Only two frame types are defined for now; the remaining type space is
// reserved for future downlink-wrapping features discussed in #4846
// (e.g. multi-path aggregation, retransmission/ACK).
const (
	downlinkFrameData      byte = 0 // payload is proxied downlink data
	downlinkFrameKeepAlive byte = 1 // payload is padding, discarded by the client
)

const (
	downlinkFrameHeaderLen  = 3      // type(1) + length(2)
	downlinkMaxFramePayload = 0xFFFF // uint16 length ceiling
)

// downlinkWriter wraps the raw server->client writer with the downlink frame
// format. It serialises data frames (written by the proxy via Write) with
// keepalive frames (written by a background goroutine via keepAlive) so the two
// never interleave mid-frame on the wire.
type downlinkWriter struct {
	sync.Mutex
	w         io.WriteCloser
	lastWrite time.Time // guarded by the mutex
}

func newDownlinkWriter(w io.WriteCloser) *downlinkWriter {
	return &downlinkWriter{w: w, lastWrite: time.Now()}
}

// Close closes the underlying writer. The keepalive goroutine stops on the next
// write error, or earlier via the request context / stream-done signals.
func (dw *downlinkWriter) Close() error {
	return dw.w.Close()
}

func (dw *downlinkWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	dw.Lock()
	defer dw.Unlock()
	written := 0
	for len(b) > 0 {
		n := len(b)
		if n > downlinkMaxFramePayload {
			n = downlinkMaxFramePayload
		}
		if err := dw.writeFrameLocked(downlinkFrameData, b[:n]); err != nil {
			return written, err
		}
		b = b[n:]
		written += n
	}
	dw.lastWrite = time.Now()
	return written, nil
}

// keepAlive writes a keepalive frame if no data has been written for at least
// idle. It is a no-op (nil error) while the downlink is active, and returns a
// non-nil error once the underlying writer is closed (stop the loop).
func (dw *downlinkWriter) keepAlive(idle time.Duration, payload []byte) error {
	dw.Lock()
	defer dw.Unlock()
	if time.Since(dw.lastWrite) < idle {
		return nil
	}
	if err := dw.writeFrameLocked(downlinkFrameKeepAlive, payload); err != nil {
		return err
	}
	dw.lastWrite = time.Now()
	return nil
}

// writeFrameLocked writes one frame in a single underlying Write so that the
// header and payload are flushed together. The caller must hold the mutex.
func (dw *downlinkWriter) writeFrameLocked(typ byte, payload []byte) error {
	frame := make([]byte, downlinkFrameHeaderLen+len(payload))
	frame[0] = typ
	binary.BigEndian.PutUint16(frame[1:downlinkFrameHeaderLen], uint16(len(payload)))
	copy(frame[downlinkFrameHeaderLen:], payload)
	_, err := dw.w.Write(frame)
	return err
}

// downlinkReader unwraps the downlink frame format on the client side. It
// yields the payload of data frames to the caller and silently discards
// keepalive frames. It is not safe for concurrent use, matching the single
// read-pump usage of the raw response body it replaces.
type downlinkReader struct {
	r         io.ReadCloser
	hdr       [downlinkFrameHeaderLen]byte
	remaining int // unread bytes of the current data frame
}

func newDownlinkReader(r io.ReadCloser) *downlinkReader {
	return &downlinkReader{r: r}
}

func (dr *downlinkReader) Read(p []byte) (int, error) {
	for {
		if dr.remaining > 0 {
			n := len(p)
			if n > dr.remaining {
				n = dr.remaining
			}
			m, err := dr.r.Read(p[:n])
			dr.remaining -= m
			return m, err
		}
		// At a frame boundary. io.EOF here is a clean end of stream;
		// a partial header is a truncated stream (io.ErrUnexpectedEOF).
		if _, err := io.ReadFull(dr.r, dr.hdr[:]); err != nil {
			return 0, err
		}
		length := int(binary.BigEndian.Uint16(dr.hdr[1:downlinkFrameHeaderLen]))
		switch dr.hdr[0] {
		case downlinkFrameData:
			dr.remaining = length
		case downlinkFrameKeepAlive:
			if length > 0 {
				if _, err := io.CopyN(io.Discard, dr.r, int64(length)); err != nil {
					return 0, err
				}
			}
		default:
			return 0, errors.New("unexpected downlink frame type: ", dr.hdr[0])
		}
	}
}

func (dr *downlinkReader) Close() error {
	return dr.r.Close()
}
