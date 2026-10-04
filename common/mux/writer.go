package mux

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
)

type Writer struct {
	dest         net.Destination
	writer       buf.Writer
	id           uint16
	followup     bool
	hasError     bool
	transferType protocol.TransferType
	globalID     [8]byte
	inbound      *session.Inbound
}

func NewWriter(id uint16, dest net.Destination, writer buf.Writer, transferType protocol.TransferType, globalID [8]byte, inbound *session.Inbound) *Writer {
	return &Writer{
		id:           id,
		dest:         dest,
		writer:       writer,
		followup:     false,
		transferType: transferType,
		globalID:     globalID,
		inbound:      inbound,
	}
}

func NewResponseWriter(id uint16, writer buf.Writer, transferType protocol.TransferType) *Writer {
	return &Writer{
		id:           id,
		writer:       writer,
		followup:     true,
		transferType: transferType,
	}
}

func (w *Writer) getNextFrameMeta() FrameMetadata {
	meta := FrameMetadata{
		SessionID: w.id,
		Target:    w.dest,
		GlobalID:  w.globalID,
		Inbound:   w.inbound,
	}

	if w.followup {
		meta.SessionStatus = SessionStatusKeep
	} else {
		w.followup = true
		meta.SessionStatus = SessionStatusNew
	}

	return meta
}

func (w *Writer) writeMetaOnly() error {
	meta := w.getNextFrameMeta()
	b := buf.New()
	if err := meta.WriteTo(b); err != nil {
		return err
	}
	return w.writer.WriteMultiBuffer(buf.MultiBuffer{b})
}

func writeMetaWithFrame(writer buf.Writer, meta FrameMetadata, data buf.MultiBuffer) error {
	frame := buf.New()
	if err := meta.WriteTo(frame); err != nil {
		return err
	}
	if _, err := serial.WriteUint16(frame, uint16(data.Len())); err != nil {
		return err
	}

	mb2 := make(buf.MultiBuffer, 0, len(data)+1)
	mb2 = append(mb2, frame)
	mb2 = append(mb2, data...)
	return writer.WriteMultiBuffer(mb2)
}

func (w *Writer) writeData(mb buf.MultiBuffer) error {
	meta := w.getNextFrameMeta()
	meta.Option.Set(OptionData)

	return writeMetaWithFrame(w.writer, meta, mb)
}

// writePackets writes each Buffer as one frame, consecutive frames share a Buffer while they fit.
func (w *Writer) writePackets(mb buf.MultiBuffer) error {
	var mb2 buf.MultiBuffer
	var frame *buf.Buffer // the last Buffer of mb2 while it takes more frames
	for !mb.IsEmpty() {
		var b *buf.Buffer
		mb, b = buf.SplitFirst(mb)
		meta := w.getNextFrameMeta()
		meta.Option.Set(OptionData)

		// what precedes the payload of a Keep frame is 268 bytes at most
		if frame == nil || frame.Available() < 268+b.Len() {
			// one Buffer per write as in stream mode, so that the carrier can apply its size limit and serve other sessions
			if len(mb2) > 0 {
				if err := w.writer.WriteMultiBuffer(mb2); err != nil {
					b.Release()
					return err
				}
				mb2 = nil
			}
			frame = buf.New()
			mb2 = append(mb2, frame)
		}
		frame.UDP = b.UDP
		if err := meta.WriteTo(frame); err != nil {
			b.Release()
			buf.ReleaseMulti(mb2)
			return err
		}
		frame.WriteByte(byte(b.Len() >> 8))
		frame.WriteByte(byte(b.Len()))
		if b.Len() > frame.Available() { // too large to share a Buffer with its own header
			mb2 = append(mb2, b)
			frame = nil
		} else {
			frame.Write(b.Bytes())
			b.Release()
		}
	}
	return w.writer.WriteMultiBuffer(mb2)
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	if mb.IsEmpty() {
		return w.writeMetaOnly()
	}

	if w.transferType == protocol.TransferTypePacket {
		return w.writePackets(mb)
	}

	for !mb.IsEmpty() {
		var chunk buf.MultiBuffer
		mb, chunk = buf.SplitSize(mb, 8*1024)
		if err := w.writeData(chunk); err != nil {
			return err
		}
	}

	return nil
}

// Close implements common.Closable.
func (w *Writer) Close() error {
	meta := FrameMetadata{
		SessionID:     w.id,
		SessionStatus: SessionStatusEnd,
	}
	if w.hasError {
		meta.Option.Set(OptionError)
	}

	frame := buf.New()
	common.Must(meta.WriteTo(frame))

	w.writer.WriteMultiBuffer(buf.MultiBuffer{frame})
	return nil
}
