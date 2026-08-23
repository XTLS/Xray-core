package bittorrent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

var bittorrentHandshake = []byte("BitTorrent protocol")

func SniffBittorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] == 19 && bytes.HasPrefix(b[1:], bittorrentHandshake) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	buffer := buf.FromBytes(b)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		return nil, common.ErrNoClue
	} else if b[0]>>4&0xF > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		return nil, common.ErrNoClue
	} else if extension != 0 && extension != 1 {
		return nil, errNotBittorrent
	}

	for extension != 0 {
		if extension != 1 {
			return nil, errNotBittorrent
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			return nil, common.ErrNoClue
		}

		var length uint8
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, common.ErrNoClue
		}
		if common.Error2(buffer.ReadBytes(int32(length))) != nil {
			return nil, common.ErrNoClue
		}
	}

	if common.Error2(buffer.ReadBytes(2)) != nil {
		return nil, common.ErrNoClue
	}

	var timestamp uint32
	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		return nil, common.ErrNoClue
	}
	if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) < 16 {
		return nil, common.ErrNoClue
	}

	// protocol_id
	if binary.BigEndian.Uint64(b[0:8]) != 0x41727101980 {
		return nil, errNotBittorrent
	}

	// action connect
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

var dhtPrefixes = [][]byte{
	[]byte("d1:ad"), // query
	[]byte("d1:rd"), // response
	[]byte("d2:ip"), // BEP-42
	[]byte("d1:el"), // error
}

func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) < 5 {
		return nil, common.ErrNoClue
	}

	for _, p := range dhtPrefixes {
		if bytes.HasPrefix(b, p) {
			return &SniffHeader{}, nil
		}
	}

	return nil, errNotBittorrent
}

var lsdPrefix = []byte("BT-SEARCH * HTTP/1.1\r\n")

func SniffLSD(b []byte) (*SniffHeader, error) {
	if len(b) < len(lsdPrefix) {
		return nil, common.ErrNoClue
	}

	if bytes.HasPrefix(b, lsdPrefix) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}
