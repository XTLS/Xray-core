package strmatcher

import (
	"encoding/binary"
	"errors"
	"io"
	"unsafe"
)

func (g *MphMatcherGroup) Serialize(w io.Writer) error {
	// header: level0 4, level1 4, rule count 4, rule data 4

	var rulesDataLen uint32
	for _, r := range g.rules {
		// 2 bytes for length
		rulesDataLen += 2 + uint32(len(r))
	}

	header := []uint32{
		uint32(len(g.level0)),
		uint32(len(g.level1)),
		uint32(len(g.rules)),
		rulesDataLen,
	}

	if err := binary.Write(w, binary.LittleEndian, header); err != nil {
		return err
	}

	// level0
	if err := binary.Write(w, binary.LittleEndian, g.level0); err != nil {
		return err
	}
	// level1
	if err := binary.Write(w, binary.LittleEndian, g.level1); err != nil {
		return err
	}

	// rules
	for _, r := range g.rules {
		if err := binary.Write(w, binary.LittleEndian, uint16(len(r))); err != nil {
			return err
		}
		if _, err := w.Write([]byte(r)); err != nil {
			return err
		}
	}

	return nil
}

func NewMphMatcherGroupFromBuffer(data []byte) (*MphMatcherGroup, error) {
	if len(data) < 16 {
		return nil, errors.New("invalid data length")
	}

	l0Len := binary.LittleEndian.Uint32(data[0:4])
	l1Len := binary.LittleEndian.Uint32(data[4:8])
	ruleCount := binary.LittleEndian.Uint32(data[8:12])
	rulesDataLen := binary.LittleEndian.Uint32(data[12:16])

	offset := 16

	// check size
	requiredSize := offset + int(l0Len)*4 + int(l1Len)*4 + int(rulesDataLen)
	if len(data) < requiredSize {
		return nil, errors.New("data truncated")
	}

	g := NewMphMatcherGroup()

	// level0
	if l0Len > 0 {
		g.level0 = unsafe.Slice((*uint32)(unsafe.Pointer(&data[offset])), l0Len)
		offset += int(l0Len) * 4
		g.level0Mask = int(l0Len) - 1
	}

	// level1
	if l1Len > 0 {
		g.level1 = unsafe.Slice((*uint32)(unsafe.Pointer(&data[offset])), l1Len)
		offset += int(l1Len) * 4
		g.level1Mask = int(l1Len) - 1
	}

	// build rules
	if ruleCount > 0 {
		g.rules = make([]string, ruleCount)
		rulesOffset := offset

		for i := range ruleCount {
			if rulesOffset+2 > len(data) {
				return nil, errors.New("rules truncated")
			}
			strLen := int(binary.LittleEndian.Uint16(data[rulesOffset : rulesOffset+2]))
			rulesOffset += 2

			if rulesOffset+strLen > len(data) {
				return nil, errors.New("rule string truncated")
			}

			strBytes := data[rulesOffset : rulesOffset+strLen]
			g.rules[i] = unsafe.String(unsafe.SliceData(strBytes), strLen)

			rulesOffset += strLen
		}
	}

	g.count = uint32(ruleCount) + 1

	return g, nil
}
