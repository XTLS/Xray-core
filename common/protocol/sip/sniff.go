package sip

import (
	"bytes"
	"errors"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "sip"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotSIP = errors.New("not SIP protocol")

func SniffSIP(b []byte) (*SniffHeader, error) {
	if len(b) < 4 {
		return nil, errNotSIP
	}

	// SIP requests start with methods like INVITE, ACK, OPTIONS, BYE, CANCEL
	if bytes.HasPrefix(b, []byte("INVITE")) ||
		bytes.HasPrefix(b, []byte("ACK")) ||
		bytes.HasPrefix(b, []byte("OPTIONS")) ||
		bytes.HasPrefix(b, []byte("BYE")) ||
		bytes.HasPrefix(b, []byte("CANCEL")) {
		return &SniffHeader{}, nil
	}

	return nil, errNotSIP
}
