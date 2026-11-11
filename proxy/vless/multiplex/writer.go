package multiplex

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

// WriteMultiBuffer submits at most two frames per carrier write.
// Each frame keeps its wire boundary and per-packet destination.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		return w.writeMetaOnly()
	}
	var frames buf.MultiBuffer
	framesInBatch := 0
	defer func() { buf.ReleaseMulti(frames) }()
	for !mb.IsEmpty() {
		var chunk buf.MultiBuffer
		if w.transferType == protocol.TransferTypeStream {
			mb, chunk = buf.SplitSize(mb, 8*1024)
		} else {
			mb2, b := buf.SplitFirst(mb)
			mb = mb2
			chunk = buf.MultiBuffer{b}
		}
		frame := buf.New()
		if len(chunk) == 1 {
			frame.UDP = chunk[0].UDP
		}
		frames = append(frames, frame)
		frames = append(frames, chunk...)
		meta := w.getNextFrameMeta()
		meta.Option.Set(OptionData)
		if err := meta.WriteTo(frame); err != nil {
			return err
		}
		if _, err := serial.WriteUint16(frame, uint16(chunk.Len())); err != nil {
			return err
		}
		framesInBatch++
		if framesInBatch == 2 {
			output := frames
			frames = nil
			framesInBatch = 0
			if err := w.writer.WriteMultiBuffer(output); err != nil {
				return err
			}
		}
	}
	if len(frames) == 0 {
		return nil
	}
	output := frames
	frames = nil
	return w.writer.WriteMultiBuffer(output)
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
