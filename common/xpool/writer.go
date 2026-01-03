package xpool

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
)

type XPoolWriter struct {
	underlying  io.Writer
	sendBuffer  *SendBuffer
	session     Session
	firstPacket bool
}

func NewXPoolWriter(w io.Writer, sb *SendBuffer, s Session) *XPoolWriter {
	return &XPoolWriter{
		underlying:  w,
		sendBuffer:  sb,
		session:     s,
		firstPacket: true,
	}
}

func (w *XPoolWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for _, b := range mb {
		if b.IsEmpty() {
			b.Release()
			continue
		}

		seq := w.session.GetNextSeq()
		ack := w.session.GetAck()
		sid := w.session.GetID()

		includeSID := w.firstPacket || seq == 0
		if includeSID {
			w.firstPacket = false
		}

		sidLen := 0
		if includeSID {
			if sid <= 65535 {
				sidLen = 2
			} else if sid <= 16777215 {
				sidLen = 3
			} else {
				sidLen = 4
			}
		}

		seqLen := 2
		if seq > 65535 || ack > 65535 {
			seqLen = 4
		}

		payloadSize := b.Len()
		payloadLenLen := 0
		if payloadSize <= 65535 {
			payloadLenLen = 2
		} else if payloadSize <= 16777215 {
			payloadLenLen = 3
		} else {
			payloadLenLen = 4
		}

		headerSize := 1 + sidLen + seqLen + seqLen + payloadLenLen

		header := make([]byte, headerSize)

		header[0] = ConstructFlags(TypeDATA, sidLen, seqLen, payloadLenLen)

		offset := 1

		if sidLen > 0 {
			writeUintBE(header[offset:], uint64(sid), sidLen)
			offset += sidLen
		}

		writeUintBE(header[offset:], uint64(seq), seqLen)
		offset += seqLen

		writeUintBE(header[offset:], uint64(ack), seqLen)
		offset += seqLen

		if payloadLenLen > 0 {
			writeUintBE(header[offset:], uint64(payloadSize), payloadLenLen)
			offset += payloadLenLen
		}

		if err := b.Prepend(header); err == nil {
		} else {
			newBuf := buf.NewWithSize(int32(headerSize) + b.Len())
			newBuf.Write(header)
			newBuf.Write(b.Bytes())
			b.Release()
			b = newBuf
		}

		if _, err := w.underlying.Write(b.Bytes()); err != nil {
			b.Release()
			return err
		}

		b.Advance(int32(headerSize)) // Restore to payload view

		if !w.sendBuffer.Add(seq, b) {
			b.Release()
		}
	}
	return nil
}

func writeUintBE(b []byte, v uint64, bytes int) {
	for i := 0; i < bytes; i++ {
		b[bytes-1-i] = byte(v >> (8 * i))
	}
}

func (w *XPoolWriter) WriteKeepAlive() error {
	seq := w.session.GetNextSeq()
	ack := w.session.GetAck()
	sid := w.session.GetID()

	includeSID := w.firstPacket || seq == 0
	if includeSID {
		w.firstPacket = false
	}

	sidLen := 0
	if includeSID {
		if sid <= 65535 {
			sidLen = 2
		} else if sid <= 16777215 {
			sidLen = 3
		} else {
			sidLen = 4
		}
	}

	seqLen := 2
	if seq > 65535 || ack > 65535 {
		seqLen = 4
	}

	headerSize := 1 + sidLen + seqLen + seqLen
	header := make([]byte, headerSize)
	header[0] = ConstructFlags(TypeDATA, sidLen, seqLen, 0)

	offset := 1
	if sidLen > 0 {
		writeUintBE(header[offset:], uint64(sid), sidLen)
		offset += sidLen
	}
	writeUintBE(header[offset:], uint64(seq), seqLen)
	offset += seqLen
	writeUintBE(header[offset:], uint64(ack), seqLen)

	_, err := w.underlying.Write(header)
	return err
}

func (w *XPoolWriter) Resend(entries []*SendEntry) error {
	for _, entry := range entries {
		b := entry.Buffer
		seq := entry.Seq
		ack := w.session.GetAck()
		sid := w.session.GetID()

		includeSID := w.firstPacket || seq == 0
		if includeSID {
			w.firstPacket = false
		}

		sidLen := 0
		if includeSID {
			if sid <= 65535 {
				sidLen = 2
			} else if sid <= 16777215 {
				sidLen = 3
			} else {
				sidLen = 4
			}
		}

		seqLen := 2
		if seq > 65535 || ack > 65535 {
			seqLen = 4
		}

		payloadSize := b.Len()
		payloadLenLen := 0
		if payloadSize <= 65535 {
			payloadLenLen = 2
		} else if payloadSize <= 16777215 {
			payloadLenLen = 3
		} else {
			payloadLenLen = 4
		}

		headerSize := 1 + sidLen + seqLen + seqLen + payloadLenLen
		header := make([]byte, headerSize)
		header[0] = ConstructFlags(TypeDATA, sidLen, seqLen, payloadLenLen)

		offset := 1
		if sidLen > 0 {
			writeUintBE(header[offset:], uint64(sid), sidLen)
			offset += sidLen
		}
		writeUintBE(header[offset:], uint64(seq), seqLen)
		offset += seqLen
		writeUintBE(header[offset:], uint64(ack), seqLen)
		offset += seqLen
		if payloadLenLen > 0 {
			writeUintBE(header[offset:], uint64(payloadSize), payloadLenLen)
			offset += payloadLenLen
		}

		// We must not modify the original buffer permanently if it's shared?
		// SendBuffer owns it.
		// If we Prepend, we modify b.start.
		// After write, we should restore it?
		// Yes, b.Advance(headerSize).

		if err := b.Prepend(header); err == nil {
			if _, err := w.underlying.Write(b.Bytes()); err != nil {
				b.Advance(int32(headerSize)) // Restore
				return err
			}
			b.Advance(int32(headerSize)) // Restore
		} else {
			// Copy
			newBuf := buf.NewWithSize(int32(headerSize) + b.Len())
			newBuf.Write(header)
			newBuf.Write(b.Bytes())
			if _, err := w.underlying.Write(newBuf.Bytes()); err != nil {
				newBuf.Release()
				return err
			}
			newBuf.Release()
		}
	}
	return nil
}

func (w *XPoolWriter) WriteEOF() error {
	seq := w.session.GetNextSeq()
	ack := w.session.GetAck()
	sid := w.session.GetID()

	includeSID := w.firstPacket || seq == 0
	if includeSID {
		w.firstPacket = false
	}

	sidLen := 0
	if includeSID {
		if sid <= 65535 {
			sidLen = 2
		} else if sid <= 16777215 {
			sidLen = 3
		} else {
			sidLen = 4
		}
	}

	seqLen := 2
	if seq > 65535 || ack > 65535 {
		seqLen = 4
	}

	headerSize := 1 + sidLen + seqLen + seqLen
	header := make([]byte, headerSize)
	header[0] = ConstructFlags(TypeEOF, sidLen, seqLen, 0)

	offset := 1
	if sidLen > 0 {
		writeUintBE(header[offset:], uint64(sid), sidLen)
		offset += sidLen
	}
	writeUintBE(header[offset:], uint64(seq), seqLen)
	offset += seqLen
	writeUintBE(header[offset:], uint64(ack), seqLen)

	_, err := w.underlying.Write(header)
	return err
}
