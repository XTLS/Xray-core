package kcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"github.com/xtls/xray-core/common"
)

func NewAEADAESGCMBasedOnSeed(seed string) cipher.AEAD {
	hashedSeed := sha256.Sum256([]byte(seed))
	aesBlock := common.Must2(aes.NewCipher(hashedSeed[:16])).(cipher.Block)
	return common.Must2(cipher.NewGCM(aesBlock)).(cipher.AEAD)
}
