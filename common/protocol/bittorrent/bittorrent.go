package bittorrent

import (
	"encoding/binary"
	"errors"

	"github.com/xtls/xray-core/common"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

const (
	utpHeaderSize            = 20
	utpVersion               = 1
	utpPacketTypeMax         = 4
	utpExtensionSelectiveAck = 1
	utpWindowSizeMax         = 16 << 20
)

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < utpHeaderSize {
		return nil, common.ErrNoClue
	}

	if b[0]&0xF != utpVersion || b[0]>>4 > utpPacketTypeMax {
		return nil, errNotBittorrent
	}

	// The initiating endpoint picks a connection id at random. Zero is what a
	// WireGuard handshake initiation presents here, because its three reserved
	// bytes fall on the version, extension and connection id fields.
	if binary.BigEndian.Uint16(b[2:4]) == 0 {
		return nil, errNotBittorrent
	}

	// timestamp_microseconds and timestamp_difference_microseconds carry the
	// sender's own clock, which bears no fixed relation to this host's, so they
	// are read but not judged. wnd_size is a receive window in bytes and stays
	// far below this bound in practice.
	if binary.BigEndian.Uint32(b[12:16]) > utpWindowSizeMax {
		return nil, errNotBittorrent
	}

	// Extension records follow the fixed header. Each carries the type of the
	// next record and its own length, terminated by a type of zero.
	// A datagram is a complete message, so a chain that does not fit inside it
	// belongs to something that is not uTP rather than to a short read.
	extension, rest := b[1], b[utpHeaderSize:]
	for extension != 0 {
		if extension != utpExtensionSelectiveAck || len(rest) < 2 {
			return nil, errNotBittorrent
		}
		// BEP 29 sizes a selective ack in whole 32 bit words.
		length := int(rest[1])
		if length < 4 || length%4 != 0 || len(rest) < 2+length {
			return nil, errNotBittorrent
		}
		extension, rest = rest[0], rest[2+length:]
	}

	return &SniffHeader{}, nil
}
