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
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	// type 4 (ST_SYN), version 1
	if b[0] != 0x41 {
		return nil, errNotBittorrent
	}

	// timestamp_difference is always 0 in new connections
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	// Walk the extension chain. Selective ack (1) and extension bits (2)
	extension, offset := b[1], 20
	for extension != 0 {
		if len(b) < offset+2 {
			return nil, errNotBittorrent
		}
		length := int(b[offset+1])
		switch extension {
		case 1: // selective ack
			if length < 4 || length%4 != 0 {
				return nil, errNotBittorrent
			}
		case 2: // extension bits: fixed 8 bytes, sent in ST_SYN by µTorrent
			if length != 8 {
				return nil, errNotBittorrent
			}
		default:
			return nil, errNotBittorrent
		}
		if len(b) < offset+2+length {
			return nil, errNotBittorrent
		}
		extension = b[offset]
		offset += 2 + length
	}

	// extensions should consume all ST_SYN payload
	if len(b) != offset {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}
