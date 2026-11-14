package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash/crc32"
)

type routeKeys interface {
	size() int
	match(*[16]byte, uint64) int
}

type standardRouteKeys []cipher.Block

// Includes the block interface and conservative per-cipher storage accounting.
var (
	routeKeyBytes    = 576
	prepareRouteKeys = prepareStandardRouteKeys
	scanRouteRaw     = scanStandardRouteRaw
)

func valid(plain *[16]byte, now uint64) bool {
	ts := binary.BigEndian.Uint64(plain[:8])
	delta := ts - now
	if ts < now {
		delta = now - ts
	}
	return ts <= 1<<63-1 && delta <= 120 && binary.BigEndian.Uint32(plain[12:]) == crc32.ChecksumIEEE(plain[:12])
}

func prepareStandardRouteKeys(keys [][16]byte) routeKeys {
	result := make(standardRouteKeys, len(keys))
	for i := range keys {
		result[i], _ = aes.NewCipher(keys[i][:])
	}
	return result
}

func (k standardRouteKeys) size() int { return len(k) * 576 }
func (k standardRouteKeys) match(query *[16]byte, now uint64) int {
	var plain [16]byte
	for i, key := range k {
		key.Decrypt(plain[:], query[:])
		if valid(&plain, now) {
			return i
		}
	}
	return -1
}

func scanStandardRouteRaw(keys [][16]byte, query *[16]byte, now uint64) int {
	var plain [16]byte
	for i := range keys {
		key, _ := aes.NewCipher(keys[i][:])
		key.Decrypt(plain[:], query[:])
		if valid(&plain, now) {
			return i
		}
	}
	return -1
}
