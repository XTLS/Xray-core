package ntp

import (
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "ntp"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotNTP = errors.New("not NTP protocol")

func SniffNTP(b []byte) (*SniffHeader, error) {
	if len(b) < 48 {
		return nil, errNotNTP
	}

	firstByte := b[0]
	_ = (firstByte >> 6) & 0x03   // Leap Indicator
	vn := (firstByte >> 3) & 0x07 // Version Number
	mode := firstByte & 0x07      // Mode

	if (vn == 3 || vn == 4) && mode == 3 {
		return &SniffHeader{}, nil
	}

	return nil, errNotNTP
}
