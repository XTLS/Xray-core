package utils

import (
	"crypto/rand"
	"strings"

	"github.com/xtls/xray-core/common/crypto"
)

func GetPadding() string {
	paddingLength := int(crypto.RandBetween(100, 1000))

	buf := make([]byte, paddingLength)
	_, err := rand.Read(buf)
	if err != nil {
		// fallback: all X if randomness fails
		return strings.Repeat("X", paddingLength)
	}

	for i := range buf {
		if buf[i]&1 == 0 {
			buf[i] = 'X'
		} else {
			buf[i] = 'Z'
		}
	}

	return string(buf)
}
