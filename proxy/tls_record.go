package proxy

import "github.com/xtls/xray-core/common/buf"

// tlsRecordTracker follows the original byte stream from its first record.
// Never search ciphertext for a new header if the stream is not valid TLS.
type tlsRecordTracker struct {
	header      [5]byte
	headerLen   int
	remaining   int32
	application bool
	invalid     bool
}

// applicationDataEnd returns the end of the first complete application-data
// record in this write once direct copy is enabled. Until then, it keeps track
// of headers and bodies without retaining or copying any payload.
func (r *tlsRecordTracker) applicationDataEnd(mb buf.MultiBuffer, enabled bool) int32 {
	if r.invalid {
		return 0
	}
	var offset int32
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		data := b.Bytes()
		for len(data) > 0 {
			if r.remaining > 0 {
				n := min(r.remaining, int32(len(data)))
				r.remaining -= n
				offset += n
				data = data[n:]
				if r.remaining == 0 && r.application && enabled {
					return offset
				}
				continue
			}
			n := copy(r.header[r.headerLen:], data)
			r.headerLen += n
			offset += int32(n)
			data = data[n:]
			if r.headerLen < len(r.header) {
				continue
			}
			// Accept handshake, change_cipher_spec, alert and application data
			// records, including a TLS 1.0 legacy record version in ClientHello.
			if r.header[0] < 20 || r.header[0] > 23 || r.header[1] != 3 || r.header[2] < 1 || r.header[2] > 3 {
				r.invalid = true
				return 0
			}
			r.remaining = int32(r.header[3])<<8 | int32(r.header[4])
			r.headerLen = 0
			r.application = r.header[0] == 23 && r.header[2] == 3
			if r.remaining == 0 {
				r.invalid = true
				return 0
			}
		}
	}
	return 0
}

// splitVisionBuffer splits at an exact byte offset, copying only the suffix of
// the buffer containing that offset. The two results have separate ownership.
func splitVisionBuffer(mb buf.MultiBuffer, offset int32) (buf.MultiBuffer, buf.MultiBuffer) {
	for i, b := range mb {
		if offset > b.Len() {
			offset -= b.Len()
			continue
		}
		prefix, suffix := buf.SplitMulti(mb, i+1)
		if offset < b.Len() {
			tail := buf.New()
			tail.Write(b.BytesFrom(offset))
			b.Resize(0, offset)
			suffix = append(buf.MultiBuffer{tail}, suffix...)
		}
		return prefix, suffix
	}
	return mb, nil
}
