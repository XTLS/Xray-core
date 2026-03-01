package sudoku

import (
	"fmt"
	"io"
	"net"
)

type packedEncoder struct {
	layout    *byteLayout
	codec     *codec
	padding   []byte
	padMarker byte
}

func newPackedEncoder(t *table, pMin, pMax int) *packedEncoder {
	e := &packedEncoder{
		layout:    t.layout,
		codec:     newCodec(t, pMin, pMax),
		padMarker: t.layout.padMarker,
		padding:   make([]byte, 0, len(t.layout.paddingPool)),
	}

	for _, b := range t.layout.paddingPool {
		if b != e.padMarker {
			e.padding = append(e.padding, b)
		}
	}
	if len(e.padding) == 0 {
		e.padding = append(e.padding, e.padMarker)
	}

	return e
}

func (e *packedEncoder) encode(p []byte) ([]byte, error) {
	out := make([]byte, 0, len(p)*2+8)
	var bitBuf uint64
	var bitCount uint8

	for _, b := range p {
		bitBuf = (bitBuf << 8) | uint64(b)
		bitCount += 8

		for bitCount >= 6 {
			bitCount -= 6
			group := byte(bitBuf >> bitCount)
			out = e.maybePad(out)
			out = append(out, e.layout.encodeGroup(group&0x3f))
			if bitCount > 0 {
				bitBuf &= (uint64(1) << bitCount) - 1
			} else {
				bitBuf = 0
			}
		}
	}

	if bitCount > 0 {
		out = e.maybePad(out)
		group := byte(bitBuf << (6 - bitCount))
		out = append(out, e.layout.encodeGroup(group&0x3f), e.padMarker)
	}

	out = e.maybePad(out)
	return out, nil
}

func (e *packedEncoder) maybePad(out []byte) []byte {
	if !e.codec.shouldPad() {
		return out
	}
	return append(out, e.padding[e.codec.rng.Intn(len(e.padding))])
}

type packedStreamDecoder struct {
	layout    *byteLayout
	padMarker byte
	bitBuf    uint64
	bitCount  int
}

func (d *packedStreamDecoder) decodeChunk(in []byte, pending []byte) ([]byte, error) {
	var err error
	d.bitBuf, d.bitCount, pending, err = decodePackedBytes(
		d.layout,
		d.padMarker,
		in,
		d.bitBuf,
		d.bitCount,
		pending,
	)
	return pending, err
}

func (d *packedStreamDecoder) reset() {
	d.bitBuf = 0
	d.bitCount = 0
}

func NewPackedTCPConn(raw net.Conn, config *Config) (net.Conn, error) {
	reader, writer, err := newPackedReaderWriter(raw, config)
	if err != nil {
		return nil, err
	}
	return newWrappedConn(raw, reader, writer), nil
}

func newPackedReaderWriter(raw net.Conn, config *Config) (io.Reader, io.Writer, error) {
	t, err := getTable(config)
	if err != nil {
		return nil, nil, err
	}

	pMin, pMax := normalizedPadding(config)
	encoder := newPackedEncoder(t, pMin, pMax)
	decoder := &packedStreamDecoder{
		layout:    t.layout,
		padMarker: t.layout.padMarker,
	}
	return newStreamReader(raw, decoder), newStreamWriter(raw, encoder.encode), nil
}

func decodePackedBytes(
	layout *byteLayout,
	padMarker byte,
	in []byte,
	bitBuf uint64,
	bitCount int,
	out []byte,
) (uint64, int, []byte, error) {
	for _, b := range in {
		if !layout.isHint(b) {
			if b == padMarker {
				bitBuf = 0
				bitCount = 0
			}
			continue
		}

		group, ok := layout.decodeGroup(b)
		if !ok {
			return bitBuf, bitCount, out, fmt.Errorf("invalid packed sudoku byte: %d", b)
		}

		bitBuf = (bitBuf << 6) | uint64(group)
		bitCount += 6

		for bitCount >= 8 {
			bitCount -= 8
			out = append(out, byte(bitBuf>>bitCount))
			if bitCount > 0 {
				bitBuf &= (uint64(1) << bitCount) - 1
			} else {
				bitBuf = 0
			}
		}
	}

	return bitBuf, bitCount, out, nil
}
