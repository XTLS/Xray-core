package rdp

import (
	"bytes"
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "rdp"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotRDP = errors.New("not RDP protocol")

func SniffRDP(b []byte) (*SniffHeader, error) {
	if len(b) < 12 {
		return nil, errNotRDP
	}

	// RDP TCP negotiation packet starts with 0x03 0x00 0x00 0x13 followed by more data
	if bytes.HasPrefix(b, []byte{0x03, 0x00, 0x00, 0x13}) {
		return &SniffHeader{}, nil
	}

	return nil, errNotRDP
}
