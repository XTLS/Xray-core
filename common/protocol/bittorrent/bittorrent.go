package bittorrent

import (
	"errors"

	"github.com/xtls/xray-core/common"
)

type SniffHeader struct {
}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffProtocolBittorrent(b []byte) (*SniffHeader, error) {
	h := &SniffHeader{}

	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return h, nil
	}

	return nil, errNotBittorrent
}

func SniffDomainBittorrent(b []byte) (*SniffHeader, error) {
	return SniffProtocolBittorrent(b)
}
