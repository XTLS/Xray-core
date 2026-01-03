package xpool

import (
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
)

type SegmentReader struct {
	reader *buf.BufferedReader
}

func NewSegmentReader(r io.Reader) *SegmentReader {
	return &SegmentReader{
		reader: &buf.BufferedReader{Reader: buf.NewReader(r)},
	}
}

func (r *SegmentReader) ReadSegment() (*Segment, error) {
	b, err := r.reader.ReadByte()
	if err != nil {
		return nil, err
	}
	flags := b

	sidLen, seqLen, payloadLenLen := ParseFlags(flags)

	remLen := sidLen + seqLen + seqLen + payloadLenLen
	headerBuf := make([]byte, remLen)
	if remLen > 0 {
		if _, err := io.ReadFull(r.reader, headerBuf); err != nil {
			return nil, err
		}
	}

	seg := &Segment{
		Flags: flags,
		Type:  GetType(flags),
	}

	offset := 0

	if sidLen > 0 {
		seg.SID = uint32(readUintBE(headerBuf[offset : offset+sidLen]))
		offset += sidLen
	}

	seg.Seq = uint32(readUintBE(headerBuf[offset : offset+seqLen]))
	offset += seqLen

	seg.Ack = uint32(readUintBE(headerBuf[offset : offset+seqLen]))
	offset += seqLen

	payloadLen := 0
	if payloadLenLen > 0 {
		payloadLen = int(readUintBE(headerBuf[offset : offset+payloadLenLen]))
	}

	if payloadLen > 0 {
		seg.Payload = buf.New()
		if _, err := seg.Payload.ReadFullFrom(r.reader, int32(payloadLen)); err != nil {
			seg.Payload.Release()
			return nil, err
		}
	}

	return seg, nil
}

type XPoolReader struct {
	segReader *SegmentReader
	session   Session
	onSegment func(*Segment)
}

func NewXPoolReader(r io.Reader, s Session, cb func(*Segment)) *XPoolReader {
	return &XPoolReader{
		segReader: NewSegmentReader(r),
		session:   s,
		onSegment: cb,
	}
}

func (r *XPoolReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	for {
		seg, err := r.segReader.ReadSegment()
		if err != nil {
			return nil, err
		}

		if r.onSegment != nil {
			r.onSegment(seg)
		}

		switch seg.Type {
		case TypeDATA:
			if seg.Payload != nil {
				return buf.MultiBuffer{seg.Payload}, nil
			}
			continue
		case TypeEOF:
			return nil, io.EOF
		case TypeRST:
			return nil, errors.New("connection reset")
		case TypePROBE:
			continue
		}
	}
}

func readUintBE(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = (v << 8) | uint64(x)
	}
	return v
}
