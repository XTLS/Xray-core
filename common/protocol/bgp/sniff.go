package bgp

import (
	"bytes"
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bgp"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBGP = errors.New("not BGP protocol")

func SniffBGP(b []byte) (*SniffHeader, error) {
	if len(b) < 18 {
		return nil, errNotBGP
	}

	// BGP marker is 16 bytes of 0xFF
	bgpMarker := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if bytes.HasPrefix(b, bgpMarker) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBGP
}
