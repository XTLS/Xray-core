package smb

import (
	"bytes"
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "smb"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotSMB = errors.New("not SMB protocol")

func SniffSMB(b []byte) (*SniffHeader, error) {
	if len(b) < 4 {
		return nil, errNotSMB
	}

	// SMB1 magic bytes: 0xFF 0x53 0x4D 0x42 ("SMB")
	if bytes.HasPrefix(b, []byte{0xFF, 0x53, 0x4D, 0x42}) {
		return &SniffHeader{}, nil
	}

	// SMB2/SMB3 magic bytes: 0xFE 0x53 0x4D 0x42
	if bytes.HasPrefix(b, []byte{0xFE, 0x53, 0x4D, 0x42}) {
		return &SniffHeader{}, nil
	}

	return nil, errNotSMB
}
