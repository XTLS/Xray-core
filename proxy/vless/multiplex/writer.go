package multiplex

import (
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
)

// encodeBatch moves up to four complete wire frames from raw caller custody.
// An offer without buffers contains metadata only.
func (s *Session) encodeBatch(mb *buf.MultiBuffer) (frames buf.MultiBuffer, err error) {
	for n := 0; n < 4; n++ {
		frame := buf.NewWithSize(1024)
		frames = append(frames, frame)
		meta := FrameMetadata{
			SessionID: s.ID, Target: s.target, GlobalID: s.globalID,
			Inbound: s.inbound, SessionStatus: SessionStatusKeep,
		}
		if s.first {
			s.first = false
			meta.SessionStatus = SessionStatusNew
		}
		if len(*mb) == 0 || s.transferType == protocol.TransferTypeStream && (*mb).IsEmpty() {
			*mb = buf.ReleaseMulti(*mb)
			return frames, meta.WriteTo(frame)
		}
		var chunk buf.MultiBuffer
		if s.transferType == protocol.TransferTypeStream {
			*mb, chunk = buf.SplitSize(*mb, 8*1024)
		} else {
			mb2, b := buf.SplitFirst(*mb)
			*mb = mb2
			chunk = buf.MultiBuffer{b}
		}
		if len(chunk) == 1 {
			frame.UDP = chunk[0].UDP
		}
		frames = append(frames, chunk...)
		meta.Option.Set(OptionData)
		if err := meta.WriteTo(frame); err != nil {
			return frames, err
		}
		if _, err := serial.WriteUint16(frame, uint16(chunk.Len())); err != nil {
			return frames, err
		}
		if s.transferType == protocol.TransferTypeStream && (*mb).IsEmpty() {
			*mb = buf.ReleaseMulti(*mb)
		}
		if len(*mb) == 0 {
			break
		}
	}
	return frames, nil
}

func endFrame(id uint16, failed bool) buf.MultiBuffer {
	meta := FrameMetadata{SessionID: id, SessionStatus: SessionStatusEnd}
	if failed {
		meta.Option.Set(OptionError)
	}
	frame := buf.NewWithSize(1024)
	common.Must(meta.WriteTo(frame))
	return buf.MultiBuffer{frame}
}
