// Package framing implements the length-prefixed JSON message framing used by
// the olcrtc control and handshake protocols.
//
// Wire format: 4-byte big-endian length followed by that many bytes of body.
// Body interpretation (JSON, protobuf, etc.) is up to the caller; this package
// only deals with byte-level framing.
package framing

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// ErrFrameTooLarge is returned when a frame exceeds the configured max size.
var ErrFrameTooLarge = errors.New("frame too large")

// WriteJSON marshals msg as JSON and writes it framed.
func WriteJSON(w io.Writer, msg any, maxSize int) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return WriteBytes(w, body, maxSize)
}

// WriteBytes writes body as a single length-prefixed frame.
func WriteBytes(w io.Writer, body []byte, maxSize int) error {
	if maxSize > 0 && len(body) > maxSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(body), maxSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body))) //nolint:gosec // size bounded by maxSize check
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write hdr: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	return nil
}

// ReadBytes reads one length-prefixed frame from r.
func ReadBytes(r io.Reader, maxSize int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read hdr: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if maxSize > 0 && n > uint32(maxSize) { //nolint:gosec // maxSize is non-negative
		return nil, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, n, maxSize)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return buf, nil
}
