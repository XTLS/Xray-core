package shadowsocks_2022

import (
	"encoding/base64"
	"strings"

	"lukechampine.com/blake3"
)

const (
	ContextSessionSubKey  = "shadowsocks 2022 session subkey"
	ContextIdentitySubKey = "shadowsocks 2022 identity subkey"
)

// ParseKey decodes a base64 or raw PSK key string and validates its length
func ParseKey(key string, keyLength int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		raw = []byte(key)
	}
	if len(raw) != keyLength {
		return nil, ErrBadKey
	}
	return raw, nil
}

func ParsePSKList(password string, keyLength int) ([][]byte, error) {
	parts := strings.Split(password, ":")
	pskList := make([][]byte, len(parts))
	for i, part := range parts {
		norm, err := ParseKey(part, keyLength)
		if err != nil {
			return nil, err
		}
		pskList[i] = norm
	}
	return pskList, nil
}

func deriveSubKey(ctx string, psk, salt []byte, keyLength int) []byte {
	var keyMaterial [64]byte
	kmLen := len(psk) + len(salt)
	copy(keyMaterial[:], psk)
	copy(keyMaterial[len(psk):], salt)
	out := make([]byte, keyLength)
	blake3.DeriveKey(out, ctx, keyMaterial[:kmLen])
	return out
}

func DeriveSessionSubKey(psk, salt []byte, keyLength int) []byte {
	return deriveSubKey(ContextSessionSubKey, psk, salt, keyLength)
}

func DeriveIdentitySubKey(psk, salt []byte, keyLength int) []byte {
	return deriveSubKey(ContextIdentitySubKey, psk, salt, keyLength)
}

func DeriveUserPSKHash(userPSK []byte) [AESBlockSize]byte {
	h := blake3.Sum512(userPSK)
	var out [AESBlockSize]byte
	copy(out[:], h[:AESBlockSize])
	return out
}
