package ovpn

import (
	"bytes"
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "openvpn"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotOpenVPN = errors.New("not OpenVPN protocol")

func SniffOpenVPN(b []byte) (*SniffHeader, error) {
	if len(b) < 2 {
		return nil, errNotOpenVPN
	}

	if bytes.HasPrefix(b, []byte{0x38, 0x00}) {
		return &SniffHeader{}, nil
	}
	if bytes.HasPrefix(b, []byte{0x38, 0x01}) {
		return &SniffHeader{}, nil
	}

	if b[0] == 0x16 && len(b) > 5 {
		return &SniffHeader{}, nil
	}

	return nil, errNotOpenVPN
}
