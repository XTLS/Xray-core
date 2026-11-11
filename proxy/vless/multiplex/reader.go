package multiplex

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
)

// readPacket reads one complete packet; its destination belongs to the buffer.
func readPacket(reader io.Reader, dest net.Destination) (buf.MultiBuffer, error) {
	size, err := serial.ReadUint16(reader)
	if err != nil {
		return nil, err
	}
	if size > buf.Size {
		return nil, errors.New("packet size too large: ", size)
	}
	b := buf.New()
	if _, err := b.ReadFullFrom(reader, int32(size)); err != nil {
		b.Release()
		return nil, err
	}
	if dest.Network == net.Network_UDP {
		b.UDP = &dest
	}
	return buf.MultiBuffer{b}, nil
}

// copyFramePayload gathers the declared stream frame before publication. On a
// terminal read failure, preserve its accumulated bytes and observed cause.
func copyFramePayload(reader *buf.BufferedReader, s *Session, dest net.Destination) (err error) {
	var mb buf.MultiBuffer
	if s != nil && s.transferType == protocol.TransferTypePacket {
		mb, err = readPacket(reader, dest)
	} else {
		size, sizeErr := serial.ReadUint16(reader)
		if sizeErr != nil {
			return sizeErr
		}
		left := int32(size)
		for left > 0 {
			var part buf.MultiBuffer
			part, err = reader.ReadAtMost(left)
			left -= part.Len()
			if s == nil {
				buf.ReleaseMulti(part)
			} else {
				mb = buf.Compact(append(mb, part...))
			}
			if err != nil {
				break
			}
		}
	}
	if s == nil || mb.IsEmpty() {
		buf.ReleaseMulti(mb)
	} else if werr := s.output.WriteMultiBuffer(mb); werr != nil {
		s.Close() // complete frame already consumed; no drain adapter needed
	}
	return err
}
