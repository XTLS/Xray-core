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

// copyFramePayload publishes stream data as it arrives and keeps packets whole.
// A closed child discards the remainder without crossing the frame boundary.
func copyFramePayload(reader *buf.BufferedReader, s *Session, dest net.Destination) (err error) {
	packet := s != nil && s.transferType == protocol.TransferTypePacket
	var left int32
	if !packet {
		size, sizeErr := serial.ReadUint16(reader)
		if sizeErr != nil {
			return sizeErr
		}
		left = int32(size)
	}
	for packet || left > 0 {
		var mb buf.MultiBuffer
		if packet {
			mb, err = readPacket(reader, dest)
		} else {
			mb, err = reader.ReadAtMost(left)
			left -= mb.Len()
			// Coalesce cached pieces without reading more from the transport.
			for s != nil && left > 0 && reader.BufferedBytes() > 0 {
				var part buf.MultiBuffer
				part, err = reader.ReadAtMost(left)
				left -= part.Len()
				mb = append(mb, part...)
			}
		}
		if s == nil || mb.IsEmpty() {
			buf.ReleaseMulti(mb)
		} else if werr := s.output.WriteMultiBuffer(mb); werr != nil {
			s.Close()
			s = nil
		}
		if packet || err != nil {
			return err
		}
	}
	return nil
}
