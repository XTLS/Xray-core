package salamander

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	geckoFlagFragment = 0x80
	geckoHeaderSize   = 5

	geckoMinFragmentChunks = 2
	geckoMaxFragmentChunks = 8
)

var (
	errFrameTruncated = errors.New("gecko frame truncated")
	errFrameInvalid   = errors.New("gecko frame invalid")
)

// frameHeader is a Gecko fragment frame header.
// Wire layout (after Salamander decryption):
//
//	byte 0:   0x80 (fragment marker; low 7 bits reserved)
//	byte 1:   msgID
//	byte 2:   chunkIdx:4 | totalChunks:4
//	byte 3-4: padLen (uint16, big-endian)
//	then padLen random padding bytes, then the chunk payload
type frameHeader struct {
	padLen      uint16
	msgID       uint8
	chunkIdx    uint8 // < totalChunks
	totalChunks uint8 // [2, 8]
}

// encodeFrame writes a frame into out, filling the padding region with random
// bytes. out must be at least geckoHeaderSize + h.padLen + len(payload) long.
func encodeFrame(h frameHeader, payload, out []byte) (int, error) {
	if h.totalChunks < geckoMinFragmentChunks || h.totalChunks > geckoMaxFragmentChunks {
		return 0, errFrameInvalid
	}
	if h.chunkIdx >= h.totalChunks {
		return 0, errFrameInvalid
	}
	needed := geckoHeaderSize + int(h.padLen) + len(payload)
	if len(out) < needed {
		return 0, errFrameTruncated
	}
	out[0] = geckoFlagFragment
	out[1] = h.msgID
	out[2] = h.chunkIdx<<4 | h.totalChunks&0x0f
	binary.BigEndian.PutUint16(out[3:5], h.padLen)
	if _, err := rand.Read(out[geckoHeaderSize : geckoHeaderSize+int(h.padLen)]); err != nil {
		return 0, err
	}
	copy(out[geckoHeaderSize+int(h.padLen):], payload)
	return needed, nil
}

// decodeFrame parses a frame from in. The returned payload is a sub-slice of
// in (zero-copy) covering the bytes after the header and padding.
func decodeFrame(in []byte) (frameHeader, []byte, error) {
	if len(in) < geckoHeaderSize {
		return frameHeader{}, nil, errFrameTruncated
	}
	if in[0]&geckoFlagFragment == 0 {
		return frameHeader{}, nil, errFrameInvalid
	}
	h := frameHeader{
		msgID:       in[1],
		chunkIdx:    in[2] >> 4,
		totalChunks: in[2] & 0x0f,
		padLen:      binary.BigEndian.Uint16(in[3:5]),
	}
	if h.totalChunks < geckoMinFragmentChunks || h.totalChunks > geckoMaxFragmentChunks {
		return frameHeader{}, nil, errFrameInvalid
	}
	if h.chunkIdx >= h.totalChunks {
		return frameHeader{}, nil, errFrameInvalid
	}
	if geckoHeaderSize+int(h.padLen) > len(in) {
		return frameHeader{}, nil, errFrameTruncated
	}
	return h, in[geckoHeaderSize+int(h.padLen):], nil
}
