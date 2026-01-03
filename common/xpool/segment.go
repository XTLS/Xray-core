package xpool

import (
	"github.com/xtls/xray-core/common/buf"
)

type SegmentType uint8

const (
	TypeDATA  SegmentType = 0
	TypeRST   SegmentType = 1
	TypeEOF   SegmentType = 2
	TypePROBE SegmentType = 3
)

const (
	FlagPayloadLenMask  = 0x03
	FlagSIDLenMask      = 0x0C
	FlagSeqAckLenMask   = 0x10
	FlagTypeMask        = 0x60
	FlagPayloadLenShift = 0
	FlagSIDLenShift     = 2
	FlagSeqAckLenShift  = 4
	FlagTypeShift       = 5
)

// Segment represents an XPool protocol segment
type Segment struct {
	Flags   uint8
	Type    SegmentType
	SID     uint32      // Using uint32 (max 4 bytes supported by header)
	Seq     uint32
	Ack     uint32
	Payload *buf.Buffer // nil for Pure ACK
}

// ParseFlags extracts length information from the flags byte.
// Returns lengths in bytes.
func ParseFlags(flags uint8) (sidLen, seqLen, payloadLenLen int) {
	// bit 0-1: PayloadLen (00=0, 01=2B, 10=3B, 11=4B)
	switch flags & FlagPayloadLenMask {
	case 0x00:
		payloadLenLen = 0
	case 0x01:
		payloadLenLen = 2
	case 0x02:
		payloadLenLen = 3
	case 0x03:
		payloadLenLen = 4
	}

	// bit 2-3: SIDLen (00=0, 01=2B, 10=3B, 11=4B)
	switch (flags & FlagSIDLenMask) >> FlagSIDLenShift {
	case 0x00:
		sidLen = 0
	case 0x01:
		sidLen = 2
	case 0x02:
		sidLen = 3
	case 0x03:
		sidLen = 4
	}

	// bit 4: SeqAckLen (0=2B, 1=4B)
	if flags&FlagSeqAckLenMask == 0 {
		seqLen = 2
	} else {
		seqLen = 4
	}

	return
}

// GetType returns the segment type from flags
func GetType(flags uint8) SegmentType {
	return SegmentType((flags & FlagTypeMask) >> FlagTypeShift)
}

// ConstructFlags builds the flags byte.
// Note: This logic must match the manual construction in XPoolWriter.
func ConstructFlags(typeVal SegmentType, sidLen, seqLen, payloadLenLen int) uint8 {
	var f uint8

	// Type
	f |= (uint8(typeVal) << FlagTypeShift) & FlagTypeMask

	// SID Len
	var sBits uint8
	switch sidLen {
	case 0:
		sBits = 0
	case 2:
		sBits = 1
	case 3:
		sBits = 2
	case 4:
		sBits = 3
	}
	f |= (sBits << FlagSIDLenShift) & FlagSIDLenMask

	// Seq/Ack Len
	if seqLen == 4 {
		f |= FlagSeqAckLenMask
	}

	// Payload Len
	var pBits uint8
	switch payloadLenLen {
	case 0:
		pBits = 0
	case 2:
		pBits = 1
	case 3:
		pBits = 2
	case 4:
		pBits = 3
	}
	f |= (pBits << FlagPayloadLenShift) & FlagPayloadLenMask

	return f
}
