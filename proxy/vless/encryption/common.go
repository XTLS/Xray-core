package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

func encodeHeader(b []byte, l int) {
	b[0] = 23
	b[1] = 3
	b[2] = 3
	b[3] = byte(l >> 8)
	b[4] = byte(l)
}

func decodeHeader(b []byte) (int, error) {
	if b[0] == 23 && b[1] == 3 && b[2] == 3 {
		l := int(b[3])<<8 | int(b[4])
		if l < 17 || l > 17000 { // TODO
			return 0, errors.New("invalid length in record's header: " + strconv.Itoa(l))
		}
		return l, nil
	}
	return 0, errors.New("invalid record's header")
}

func newAead(c byte, k []byte) (aead cipher.AEAD) {
	if c&1 == 1 {
		block, _ := aes.NewCipher(k)
		aead, _ = cipher.NewGCM(block)
	} else {
		aead, _ = chacha20poly1305.New(k)
	}
	return
}

func increaseNonce(nonce []byte) {
	for i := range 12 {
		nonce[11-i]++
		if nonce[11-i] != 0 {
			break
		}
		if i == 11 {
			// TODO
		}
	}
}
